//! Minimal hand-rolled TOML 1.0 subset parser.
//!
//! Covers the subset the template loader needs and nothing more:
//! comments, bare keys, basic strings (with escapes), integers, booleans,
//! arrays of strings or integers, regular tables, and dotted-key tables.
//! Floats, datetimes, multiline strings, literal strings, inline tables,
//! and array tables are explicitly **not** supported and are rejected with
//! a `TomlError` rather than silently mis-parsed.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;

/// A parsed TOML value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TomlValue {
    /// A `"..."` basic string with escapes decoded.
    String(String),
    /// A decimal integer (optionally signed, optionally with `_` separators).
    Int(i64),
    /// `true` / `false`.
    Bool(bool),
    /// A homogeneous array (`[1, 2, 3]` or `["a", "b"]`).
    Array(Vec<TomlValue>),
    /// A `[section]` table.
    Table(TomlTable),
}

/// A TOML table: ordered key/value map. We use `BTreeMap` for stable
/// iteration; ordering inside one table is rarely meaningful for templates.
pub(crate) type TomlTable = BTreeMap<String, TomlValue>;

/// An error from [`parse`], with a 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TomlError {
    /// Human-readable diagnostic.
    pub message: String,
    /// 1-based line where parsing failed.
    pub line: usize,
}

impl fmt::Display for TomlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TOML error at line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for TomlError {}

/// Parses a TOML document into a top-level [`TomlTable`].
pub(crate) fn parse(input: &str) -> Result<TomlTable, TomlError> {
    let mut parser = Parser::new(input);
    parser.parse_document()
}

struct Parser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Parser {
            src,
            bytes: src.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn err<T, S: Into<String>>(&self, msg: S) -> Result<T, TomlError> {
        Err(TomlError {
            message: msg.into(),
            line: self.line,
        })
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    /// Skip ASCII spaces and tabs on the current line (no newline).
    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Skip the rest of a `# ...` comment if positioned at one.
    fn skip_comment(&mut self) {
        if self.peek() == Some(b'#') {
            while let Some(b) = self.peek() {
                if b == b'\n' {
                    break;
                }
                self.pos += 1;
            }
        }
    }

    /// Skip whitespace, comments, and newlines until the next meaningful char.
    fn skip_blank(&mut self) {
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'\n') => {
                    self.advance();
                }
                Some(b'\r') => {
                    self.pos += 1; // \r treated transparently
                }
                Some(b'#') => {
                    self.skip_comment();
                }
                _ => break,
            }
        }
    }

    fn parse_document(&mut self) -> Result<TomlTable, TomlError> {
        let mut root = TomlTable::new();
        // `current` is the path of the table currently receiving bare-key/value
        // pairs (empty == root).
        let mut current_path: Vec<String> = Vec::new();

        loop {
            self.skip_blank();
            if self.peek().is_none() {
                return Ok(root);
            }
            if self.peek() == Some(b'[') {
                // [section.sub] header
                current_path = self.parse_header()?;
                // Pre-create the table.
                ensure_table_path(&mut root, &current_path)?;
                self.expect_eol()?;
                continue;
            }
            // key = value
            let key = self.parse_key()?;
            self.skip_ws();
            if self.peek() != Some(b'=') {
                return self.err("expected '=' after key");
            }
            self.pos += 1; // '='
            self.skip_ws();
            let value = self.parse_value()?;
            let target = get_or_create_table(&mut root, &current_path)?;
            insert_dotted(target, &key, value, self.line)?;
            self.expect_eol()?;
        }
    }

    /// Parse a `[section]` or `[section.sub]` header. Returns the parsed
    /// path; caller positions at the next-line.
    fn parse_header(&mut self) -> Result<Vec<String>, TomlError> {
        debug_assert_eq!(self.peek(), Some(b'['));
        self.pos += 1; // consume '['
        if self.peek() == Some(b'[') {
            return self.err("array-of-tables `[[..]]` not supported");
        }
        self.skip_ws();
        let path = self.parse_key()?;
        self.skip_ws();
        if self.peek() != Some(b']') {
            return self.err("expected ']' to close section header");
        }
        self.pos += 1; // ']'
        Ok(path)
    }

    /// Parse a bare key or dotted-key. Returns the path components (length 1
    /// for `foo`, length > 1 for `foo.bar.baz`). Quoted keys are not
    /// supported in v1.
    fn parse_key(&mut self) -> Result<Vec<String>, TomlError> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let start = self.pos;
            while let Some(b) = self.peek() {
                if is_bare_key_char(b) {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.pos == start {
                return self.err("expected key");
            }
            // SAFETY: bare-key chars are all ASCII, so the slice is valid UTF-8.
            let part = self.src[start..self.pos].to_string();
            out.push(part);
            self.skip_ws();
            if self.peek() == Some(b'.') {
                self.pos += 1;
                continue;
            }
            break;
        }
        Ok(out)
    }

    fn parse_value(&mut self) -> Result<TomlValue, TomlError> {
        match self.peek() {
            Some(b'"') => self.parse_string().map(TomlValue::String),
            Some(b'[') => self.parse_array(),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'-') | Some(b'+') | Some(b'0'..=b'9') => self.parse_integer(),
            Some(b'\'') => self.err("literal strings ('...') are not supported"),
            Some(b'{') => self.err("inline tables are not supported"),
            Some(c) => self.err(format!(
                "unexpected character '{}' starting value",
                c as char
            )),
            None => self.err("unexpected end of input"),
        }
    }

    fn parse_string(&mut self) -> Result<String, TomlError> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1; // opening '"'
        // Reject triple-quoted multiline strings.
        if self.peek() == Some(b'"') && self.bytes.get(self.pos + 1) == Some(&b'"') {
            return self.err("multiline strings are not supported");
        }
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return self.err("unterminated string"),
                Some(b'\n') => return self.err("newline inside string"),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        None => return self.err("unterminated escape"),
                        Some(b'n') => {
                            out.push('\n');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            out.push('\t');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            out.push('\r');
                            self.pos += 1;
                        }
                        Some(b'"') => {
                            out.push('"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            out.push('\\');
                            self.pos += 1;
                        }
                        Some(b'x') => {
                            // \xHH — two hex digits.
                            self.pos += 1;
                            let h1 = self.expect_hex_digit()?;
                            let h2 = self.expect_hex_digit()?;
                            out.push(((h1 << 4) | h2) as char);
                        }
                        Some(other) => {
                            return self.err(format!("unknown escape '\\{}'", other as char));
                        }
                    }
                }
                Some(b) => {
                    // Multi-byte UTF-8 sequences pass through unchanged.
                    out.push(b as char);
                    self.pos += 1;
                }
            }
        }
    }

    fn expect_hex_digit(&mut self) -> Result<u8, TomlError> {
        let v = match self.peek() {
            Some(b @ b'0'..=b'9') => b - b'0',
            Some(b @ b'a'..=b'f') => b - b'a' + 10,
            Some(b @ b'A'..=b'F') => b - b'A' + 10,
            _ => return self.err("expected hex digit in \\x escape"),
        };
        self.pos += 1;
        Ok(v)
    }

    fn parse_bool(&mut self) -> Result<TomlValue, TomlError> {
        if self.src[self.pos..].starts_with("true") {
            self.pos += 4;
            Ok(TomlValue::Bool(true))
        } else if self.src[self.pos..].starts_with("false") {
            self.pos += 5;
            Ok(TomlValue::Bool(false))
        } else {
            self.err("expected `true` or `false`")
        }
    }

    fn parse_integer(&mut self) -> Result<TomlValue, TomlError> {
        let start = self.pos;
        if matches!(self.peek(), Some(b'+') | Some(b'-')) {
            self.pos += 1;
        }
        let digits_start = self.pos;
        let mut saw_digit = false;
        let mut prev_underscore = false;
        let mut prev_digit = false;
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' => {
                    saw_digit = true;
                    prev_underscore = false;
                    prev_digit = true;
                    self.pos += 1;
                }
                b'_' => {
                    if !prev_digit || prev_underscore {
                        return self.err("misplaced '_' in integer");
                    }
                    prev_underscore = true;
                    prev_digit = false;
                    self.pos += 1;
                }
                b'.' | b'e' | b'E' => {
                    return self.err("floats are not supported");
                }
                _ => break,
            }
        }
        if !saw_digit {
            return self.err("expected digits");
        }
        if prev_underscore {
            return self.err("trailing '_' in integer");
        }
        // Reject obvious mis-flavors of TOML integers we don't support.
        let raw_digits = &self.src[digits_start..self.pos];
        let cleaned: String = raw_digits.chars().filter(|c| *c != '_').collect();
        let sign = &self.src[start..digits_start];
        let combined = format!("{sign}{cleaned}");
        let n: i64 = combined.parse().map_err(|_| TomlError {
            message: format!("integer overflow or invalid integer: {combined}"),
            line: self.line,
        })?;
        Ok(TomlValue::Int(n))
    }

    fn parse_array(&mut self) -> Result<TomlValue, TomlError> {
        debug_assert_eq!(self.peek(), Some(b'['));
        self.pos += 1;
        let mut out: Vec<TomlValue> = Vec::new();
        let mut element_kind: Option<&'static str> = None;
        loop {
            self.skip_blank();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(TomlValue::Array(out));
            }
            let v = self.parse_value()?;
            let kind = match &v {
                TomlValue::String(_) => "string",
                TomlValue::Int(_) => "int",
                TomlValue::Bool(_) => "bool",
                TomlValue::Array(_) => return self.err("nested arrays are not supported"),
                TomlValue::Table(_) => return self.err("inline tables are not supported"),
            };
            if let Some(k) = element_kind {
                if k != kind {
                    return self.err(format!("mixed-type array: expected {k}, found {kind}"));
                }
            } else {
                element_kind = Some(kind);
            }
            out.push(v);
            self.skip_blank();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    continue;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(TomlValue::Array(out));
                }
                _ => return self.err("expected ',' or ']' in array"),
            }
        }
    }

    /// Expect the rest of the current line to be a comment or empty; advance
    /// past the terminating newline (if any).
    fn expect_eol(&mut self) -> Result<(), TomlError> {
        self.skip_ws();
        self.skip_comment();
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.advance();
                Ok(())
            }
            Some(b'\r') => {
                self.pos += 1;
                if self.peek() == Some(b'\n') {
                    self.advance();
                }
                Ok(())
            }
            Some(c) => self.err(format!("trailing content after value: '{}'", c as char)),
        }
    }
}

fn is_bare_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn ensure_table_path(root: &mut TomlTable, path: &[String]) -> Result<(), TomlError> {
    let mut cur = root;
    for (i, k) in path.iter().enumerate() {
        let entry = cur
            .entry(k.clone())
            .or_insert_with(|| TomlValue::Table(TomlTable::new()));
        match entry {
            TomlValue::Table(t) => {
                cur = t;
            }
            _ => {
                return Err(TomlError {
                    message: format!(
                        "key `{}` is not a table (collides with another value)",
                        path[..=i].join(".")
                    ),
                    line: 0,
                });
            }
        }
    }
    Ok(())
}

fn get_or_create_table<'r>(
    root: &'r mut TomlTable,
    path: &[String],
) -> Result<&'r mut TomlTable, TomlError> {
    let mut cur = root;
    for k in path {
        let entry = cur
            .entry(k.clone())
            .or_insert_with(|| TomlValue::Table(TomlTable::new()));
        cur = match entry {
            TomlValue::Table(t) => t,
            _ => {
                return Err(TomlError {
                    message: format!("key `{k}` is not a table"),
                    line: 0,
                });
            }
        };
    }
    Ok(cur)
}

fn insert_dotted(
    target: &mut TomlTable,
    path: &[String],
    value: TomlValue,
    line: usize,
) -> Result<(), TomlError> {
    if path.is_empty() {
        return Err(TomlError {
            message: "empty key".into(),
            line,
        });
    }
    let (last, prefix) = path.split_last().unwrap();
    let mut cur = target;
    for k in prefix {
        let entry = cur
            .entry(k.clone())
            .or_insert_with(|| TomlValue::Table(TomlTable::new()));
        cur = match entry {
            TomlValue::Table(t) => t,
            _ => {
                return Err(TomlError {
                    message: format!("key `{k}` is not a table"),
                    line,
                });
            }
        };
    }
    if cur.contains_key(last) {
        return Err(TomlError {
            message: format!("duplicate key `{last}`"),
            line,
        });
    }
    cur.insert(last.clone(), value);
    Ok(())
}

// --- helpers used by the template loader -----------------------------------

impl TomlValue {
    /// Borrow as a string, or `None` if the value is not a string.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            TomlValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
    /// Borrow as an `i64`, or `None`.
    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            TomlValue::Int(n) => Some(*n),
            _ => None,
        }
    }
    /// Borrow as a `bool`, or `None`.
    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            TomlValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    /// Borrow as an array, or `None`.
    pub(crate) fn as_array(&self) -> Option<&[TomlValue]> {
        match self {
            TomlValue::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }
    /// Borrow as a table, or `None`.
    pub(crate) fn as_table(&self) -> Option<&TomlTable> {
        match self {
            TomlValue::Table(t) => Some(t),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(input: &str) -> TomlTable {
        parse(input).expect("parse")
    }

    #[test]
    fn parses_empty_document() {
        let r = t("");
        assert!(r.is_empty());
    }

    #[test]
    fn parses_top_level_pairs() {
        let r = t(r#"name = "tls-server"
default_days = 365
critical = true
"#);
        assert_eq!(r["name"].as_str().unwrap(), "tls-server");
        assert_eq!(r["default_days"].as_int().unwrap(), 365);
        assert!(r["critical"].as_bool().unwrap());
    }

    #[test]
    fn parses_section_header() {
        let r = t(r#"name = "x"

[basic_constraints]
ca = false
"#);
        let bc = r["basic_constraints"].as_table().unwrap();
        assert!(!bc["ca"].as_bool().unwrap());
    }

    #[test]
    fn parses_dotted_section_header() {
        let r = t(r#"[a.b.c]
x = 1
"#);
        let a = r["a"].as_table().unwrap();
        let b = a["b"].as_table().unwrap();
        let c = b["c"].as_table().unwrap();
        assert_eq!(c["x"].as_int().unwrap(), 1);
    }

    #[test]
    fn parses_string_arrays() {
        let r = t(r#"urls = ["http://a", "http://b"]"#);
        let urls = r["urls"].as_array().unwrap();
        assert_eq!(urls[0].as_str().unwrap(), "http://a");
        assert_eq!(urls[1].as_str().unwrap(), "http://b");
    }

    #[test]
    fn parses_integer_arrays_with_separators() {
        let r = t(r#"v = [1, 2_000, -3]"#);
        let v = r["v"].as_array().unwrap();
        assert_eq!(v[0].as_int().unwrap(), 1);
        assert_eq!(v[1].as_int().unwrap(), 2000);
        assert_eq!(v[2].as_int().unwrap(), -3);
    }

    #[test]
    fn parses_comments_and_blank_lines() {
        let r = t(
            "# leading comment\n\n# another\nname = \"x\"  # trailing\nages = [1, 2] # trailing 2\n",
        );
        assert_eq!(r["name"].as_str().unwrap(), "x");
        assert_eq!(r["ages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn parses_escape_sequences() {
        let r = t(r#"s = "a\nb\t\"\\\x41""#);
        assert_eq!(r["s"].as_str().unwrap(), "a\nb\t\"\\A");
    }

    #[test]
    fn parses_multiline_array() {
        let r = t("v = [\n  \"a\",\n  \"b\",\n  \"c\",\n]\n");
        let v = r["v"].as_array().unwrap();
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn rejects_unclosed_string() {
        assert!(parse(r#"x = "abc"#).is_err());
    }

    #[test]
    fn rejects_unknown_escape() {
        assert!(parse(r#"x = "a\q""#).is_err());
    }

    #[test]
    fn rejects_duplicate_key() {
        assert!(parse("a = 1\na = 2\n").is_err());
    }

    #[test]
    fn rejects_unterminated_array() {
        assert!(parse("v = [1, 2").is_err());
    }

    #[test]
    fn rejects_mixed_type_array() {
        assert!(parse(r#"v = [1, "x"]"#).is_err());
    }

    #[test]
    fn rejects_floats() {
        assert!(parse("x = 1.5").is_err());
    }

    #[test]
    fn rejects_literal_strings() {
        assert!(parse("x = 'lit'").is_err());
    }

    #[test]
    fn rejects_inline_tables() {
        assert!(parse("x = { a = 1 }").is_err());
    }

    #[test]
    fn rejects_array_of_tables_header() {
        assert!(parse("[[foo]]\n").is_err());
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse("a = 1 garbage\n").is_err());
    }

    #[test]
    fn rejects_misplaced_underscore() {
        assert!(parse("a = _1").is_err());
        assert!(parse("a = 1__2").is_err());
        assert!(parse("a = 1_").is_err());
    }

    #[test]
    fn line_numbers_track_with_errors() {
        let e = parse("a = 1\nb = 2\nc = bogus\n").unwrap_err();
        assert_eq!(e.line, 3);
    }

    #[test]
    fn parses_negative_and_positive_ints() {
        let r = t("a = -7\nb = +3\n");
        assert_eq!(r["a"].as_int().unwrap(), -7);
        assert_eq!(r["b"].as_int().unwrap(), 3);
    }

    #[test]
    fn dotted_keys_in_value_position() {
        let r = t("a.b = 1\na.c = 2\n");
        let a = r["a"].as_table().unwrap();
        assert_eq!(a["b"].as_int().unwrap(), 1);
        assert_eq!(a["c"].as_int().unwrap(), 2);
    }
}
