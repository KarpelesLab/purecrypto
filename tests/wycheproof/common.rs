//! Loader for the converted Wycheproof vectors in `testdata/wycheproof/`.
//!
//! The files are produced by `tools/wycheproof/convert.py` from the upstream
//! `testvectors_v1/*.json`; see that script for the line format. Every test
//! module in this harness goes through [`run`], which walks one file, hands
//! each `(group, case)` to a closure, and fails the test with a listing of
//! every mismatching `tcId` (rather than the first one) so a regression shows
//! its whole shape at once.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::PathBuf;

/// Expected outcome of a Wycheproof test case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected {
    Valid,
    Invalid,
    /// Legal-but-discouraged input (e.g. a non-canonical encoding). The
    /// implementation may accept or reject; a harness may tighten this per
    /// flag.
    Acceptable,
}

/// An ordered `key=value` record (a group header or a single test case).
#[derive(Clone, Debug, Default)]
pub struct Fields(Vec<(String, String)>);

impl Fields {
    fn parse(line: &str) -> Fields {
        let mut out = Vec::new();
        let mut rest = line;
        while !rest.is_empty() {
            let (kv, tail) = match rest.split_once(' ') {
                Some((kv, tail)) => (kv, tail),
                None => (rest, ""),
            };
            let (k, v) = kv.split_once('=').expect("key=value");
            if k == "comment" {
                // The comment runs to end of line.
                let v = if tail.is_empty() {
                    v.to_string()
                } else {
                    format!("{v} {tail}")
                };
                out.push((k.to_string(), percent_decode(&v)));
                break;
            }
            out.push((k.to_string(), percent_decode(v)));
            rest = tail;
        }
        Fields(out)
    }

    /// Raw string value of `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Whether `key` is present at all (an empty value still counts).
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// String value of `key`; panics when absent.
    pub fn str(&self, key: &str) -> &str {
        self.get(key)
            .unwrap_or_else(|| panic!("missing field {key:?} in {:?}", self.0))
    }

    /// Hex-decoded value of `key`; panics when absent or not hex.
    pub fn hex(&self, key: &str) -> Vec<u8> {
        from_hex(self.str(key))
    }

    /// Hex value of `key` decoded into a fixed-size array; `None` when the
    /// length does not match (a common "invalid" shape for keys and nonces).
    pub fn hex_array<const N: usize>(&self, key: &str) -> Option<[u8; N]> {
        self.hex(key).try_into().ok()
    }

    /// Integer value of `key`.
    pub fn int(&self, key: &str) -> u64 {
        self.str(key)
            .parse()
            .unwrap_or_else(|_| panic!("field {key:?} is not an integer"))
    }

    /// The `flags` list (possibly empty).
    pub fn flags(&self) -> Vec<&str> {
        self.get("flags")
            .map(|f| f.split(',').filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }

    /// Whether `flag` is set on this record.
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags().contains(&flag)
    }

    /// The `result` field.
    pub fn expected(&self) -> Expected {
        match self.str("result") {
            "valid" => Expected::Valid,
            "invalid" => Expected::Invalid,
            "acceptable" => Expected::Acceptable,
            other => panic!("unknown result {other:?}"),
        }
    }

    /// The `tcId` of a test case.
    pub fn tc_id(&self) -> u64 {
        self.int("tcId")
    }

    /// The comment, or an empty string.
    pub fn comment(&self) -> &str {
        self.get("comment").unwrap_or("")
    }
}

/// A test group: its header fields and its test cases.
#[derive(Clone, Debug, Default)]
pub struct Group {
    pub fields: Fields,
    pub tests: Vec<Fields>,
}

/// One converted vector file.
#[derive(Clone, Debug, Default)]
pub struct TestFile {
    pub name: String,
    pub header: String,
    pub groups: Vec<Group>,
}

/// Where the converted vectors live.
pub fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("wycheproof")
        .join(format!("{name}.txt"))
}

/// Loads `testdata/wycheproof/<name>.txt`.
pub fn load(name: &str) -> TestFile {
    let path = vector_path(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut file = TestFile {
        name: name.to_string(),
        ..Default::default()
    };
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("# ") {
            file.header = h.to_string();
        } else if let Some(g) = line.strip_prefix("G ") {
            file.groups.push(Group {
                fields: Fields::parse(g),
                tests: Vec::new(),
            });
        } else if let Some(t) = line.strip_prefix("T ") {
            file.groups
                .last_mut()
                .expect("T before G")
                .tests
                .push(Fields::parse(t));
        } else if line == "G" {
            file.groups.push(Group::default());
        } else if !line.trim().is_empty() {
            panic!("{}: unparseable line {line:?}", path.display());
        }
    }
    assert!(!file.groups.is_empty(), "{name}: no test groups");
    file
}

/// Outcome of running one case through the implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The implementation accepted the input and produced the expected
    /// output (or verified successfully).
    Accepted,
    /// The implementation rejected the input.
    Rejected,
    /// The implementation accepted the input but produced the wrong output.
    /// Always a failure, regardless of the expected result.
    Wrong(&'static str),
    /// The group / case uses a parameter this library does not implement
    /// (e.g. a truncated GCM tag). Counted, never a failure.
    Skipped,
}

/// Aggregate counts for one file, printed on success so the test log shows
/// what was actually exercised.
#[derive(Debug, Default)]
pub struct Tally {
    pub valid: usize,
    pub invalid: usize,
    pub acceptable: usize,
    pub skipped: usize,
}

/// Runs every case of `file` through `f` and asserts the outcome matches
/// the expected result: `valid` must be [`Outcome::Accepted`], `invalid`
/// must be [`Outcome::Rejected`], `acceptable` may be either unless
/// `strict_acceptable(case)` says it must be rejected.
pub fn run_with<F, S>(file: &TestFile, mut strict: S, mut f: F) -> Tally
where
    F: FnMut(&Fields, &Fields) -> Outcome,
    S: FnMut(&Fields, &Fields) -> Option<Expected>,
{
    let mut tally = Tally::default();
    let mut failures = String::new();
    let mut nfail = 0usize;
    for group in &file.groups {
        for case in &group.tests {
            let outcome = f(&group.fields, case);
            let mut expected = case.expected();
            if expected == Expected::Acceptable {
                if let Some(e) = strict(&group.fields, case) {
                    expected = e;
                }
            }
            let ok = match (outcome, expected) {
                (Outcome::Skipped, _) => {
                    tally.skipped += 1;
                    continue;
                }
                (Outcome::Wrong(_), _) => false,
                (Outcome::Accepted, Expected::Valid) => true,
                (Outcome::Rejected, Expected::Invalid) => true,
                (_, Expected::Acceptable) => true,
                _ => false,
            };
            if ok {
                match case.expected() {
                    Expected::Valid => tally.valid += 1,
                    Expected::Invalid => tally.invalid += 1,
                    Expected::Acceptable => tally.acceptable += 1,
                }
            } else {
                nfail += 1;
                if nfail <= 40 {
                    let _ = writeln!(
                        failures,
                        "  tcId {} expected {:?} got {:?} flags={:?} comment={:?}",
                        case.tc_id(),
                        expected,
                        outcome,
                        case.flags(),
                        case.comment()
                    );
                }
            }
        }
    }
    let total = tally.valid + tally.invalid + tally.acceptable;
    assert!(
        nfail == 0,
        "{}: {nfail} mismatching case(s) out of {} (+{} skipped):\n{failures}",
        file.name,
        total + nfail,
        tally.skipped
    );
    assert!(
        total > 0,
        "{}: every case was skipped; the harness exercised nothing",
        file.name
    );
    println!(
        "{}: {} valid, {} invalid, {} acceptable, {} skipped",
        file.name, tally.valid, tally.invalid, tally.acceptable, tally.skipped
    );
    tally
}

/// [`run_with`] with no tightening of `acceptable` cases.
pub fn run<F>(file: &TestFile, f: F) -> Tally
where
    F: FnMut(&Fields, &Fields) -> Outcome,
{
    run_with(file, |_, _| None, f)
}

/// Loads and runs a file in one call.
pub fn check<F>(name: &str, f: F) -> Tally
where
    F: FnMut(&Fields, &Fields) -> Outcome,
{
    run(&load(name), f)
}

/// Hex decoding (upper or lower case, even length).
pub fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| panic!("bad hex {s:?}")))
        .collect()
}

fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).expect("utf-8")
}

/// Convenience: map a `Result`-returning verify/decrypt to an [`Outcome`].
pub fn outcome_of<T, E>(r: Result<T, E>) -> Outcome {
    match r {
        Ok(_) => Outcome::Accepted,
        Err(_) => Outcome::Rejected,
    }
}

/// Convenience: compare a produced value with the expected bytes, mapping a
/// mismatch to [`Outcome::Wrong`].
pub fn check_eq(actual: &[u8], expected: &[u8], what: &'static str) -> Outcome {
    if actual == expected {
        Outcome::Accepted
    } else {
        Outcome::Wrong(what)
    }
}
