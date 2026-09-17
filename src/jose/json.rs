//! A small, strict JSON parser and serializer (RFC 8259) for JOSE headers
//! and JWKs.
//!
//! It accepts exactly the RFC 8259 grammar: objects, arrays, strings with
//! the standard escapes (including `\uXXXX` with UTF-16 surrogate pairs),
//! numbers, `true`, `false` and `null`, separated by the four JSON
//! whitespace characters. It rejects duplicate object member names (RFC 7515
//! §5.2 step 2 / RFC 7516 §5.2 step 4 require it for headers; a duplicate is
//! also an obvious vector for parser-differential attacks), unescaped control
//! characters, lone surrogates, trailing data and nesting deeper than
//! [`MAX_DEPTH`]. The parser is recursive, so the depth cap is what bounds
//! stack use on hostile input.
//!
//! Numbers are kept as their validated source text ([`Number`]); the only
//! numeric header parameter JOSE defines (`p2c`) is a non-negative integer,
//! and keeping the text avoids any float rounding question.

use super::Error;
use alloc::string::String;
use alloc::vec::Vec;

/// Maximum nesting depth of arrays/objects the parser accepts.
pub const MAX_DEPTH: usize = 32;

/// A JSON number, kept as its validated source text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number(String);

impl Number {
    /// The number's source text (e.g. `"1300819380"`, `"-1.5e3"`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The value as a `u64` when the text is a plain non-negative integer
    /// (no sign, fraction or exponent) that fits.
    pub fn as_u64(&self) -> Option<u64> {
        if self.0.is_empty() || !self.0.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        self.0.parse().ok()
    }

    /// Builds a number from a `u64`.
    pub fn from_u64(v: u64) -> Self {
        Number(alloc::format!("{v}"))
    }
}

/// A JSON object: an ordered list of `(name, value)` members with unique
/// names.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object(Vec<(String, Value)>);

impl Object {
    /// An empty object.
    pub fn new() -> Self {
        Object(Vec::new())
    }

    /// The value of member `name`, if present.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// The string value of member `name`; `None` when absent.
    /// `Err(Malformed)` when present but not a string.
    pub fn get_str(&self, name: &str) -> Result<Option<&str>, Error> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(Error::Malformed),
        }
    }

    /// The string value of member `name`, required.
    pub fn require_str(&self, name: &str) -> Result<&str, Error> {
        self.get_str(name)?.ok_or(Error::Malformed)
    }

    /// The object value of member `name`; `None` when absent, `Err` when
    /// present but not an object.
    pub fn get_object(&self, name: &str) -> Result<Option<&Object>, Error> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Object(o)) => Ok(Some(o)),
            Some(_) => Err(Error::Malformed),
        }
    }

    /// The array value of member `name`; `None` when absent, `Err` when
    /// present but not an array.
    pub fn get_array(&self, name: &str) -> Result<Option<&[Value]>, Error> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Array(a)) => Ok(Some(a)),
            Some(_) => Err(Error::Malformed),
        }
    }

    /// Whether member `name` exists.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Appends a member. Returns `Err(Malformed)` if `name` already exists.
    pub fn insert(&mut self, name: &str, value: Value) -> Result<(), Error> {
        if self.contains(name) {
            return Err(Error::Malformed);
        }
        self.0.push((String::from(name), value));
        Ok(())
    }

    /// Appends a string member (see [`insert`](Self::insert)).
    pub fn insert_str(&mut self, name: &str, value: &str) -> Result<(), Error> {
        self.insert(name, Value::String(String::from(value)))
    }

    /// Iterates over the members in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the object has no members.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Serializes the object as compact JSON.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        write_object(self, &mut out);
        out
    }
}

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Object),
}

impl Value {
    /// The string payload of a `Value::String`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The object payload of a `Value::Object`.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Serializes the value as compact JSON.
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        write_value(self, &mut out);
        out
    }
}

/// Parses a complete JSON text (any value, surrounded by optional
/// whitespace).
pub fn parse(text: &str) -> Result<Value, Error> {
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.value(0)?;
    p.skip_ws();
    if p.pos != p.s.len() {
        return Err(Error::Json);
    }
    Ok(v)
}

/// Parses a JSON text that must be an object.
pub fn parse_object(text: &str) -> Result<Object, Error> {
    match parse(text)? {
        Value::Object(o) => Ok(o),
        _ => Err(Error::Json),
    }
}

/// Parses UTF-8 bytes as a JSON object.
pub fn parse_object_bytes(bytes: &[u8]) -> Result<Object, Error> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error::Json)?;
    parse_object(text)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.pos += 1;
        }
    }

    fn expect(&mut self, lit: &[u8]) -> Result<(), Error> {
        if self.s[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(Error::Json)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        match self.peek().ok_or(Error::Json)? {
            b'{' => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Json);
                }
                self.pos += 1;
                self.object(depth + 1).map(Value::Object)
            }
            b'[' => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Json);
                }
                self.pos += 1;
                self.array(depth + 1).map(Value::Array)
            }
            b'"' => {
                self.pos += 1;
                self.string().map(Value::String)
            }
            b't' => self.expect(b"true").map(|()| Value::Bool(true)),
            b'f' => self.expect(b"false").map(|()| Value::Bool(false)),
            b'n' => self.expect(b"null").map(|()| Value::Null),
            b'-' | b'0'..=b'9' => self.number().map(Value::Number),
            _ => Err(Error::Json),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Object, Error> {
        let mut obj = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(obj);
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(Error::Json);
            }
            self.pos += 1;
            let name = self.string()?;
            self.skip_ws();
            self.expect(b":")?;
            self.skip_ws();
            let value = self.value(depth)?;
            // Duplicate member names are rejected (Error::Json, not
            // Malformed: the text is not an acceptable JSON text for us).
            obj.insert(&name, value).map_err(|_| Error::Json)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(obj);
                }
                _ => return Err(Error::Json),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Vec<Value>, Error> {
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(items);
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(items);
                }
                _ => return Err(Error::Json),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let h = self.s.get(self.pos..self.pos + 4).ok_or(Error::Json)?;
        let mut v = 0u32;
        for &c in h {
            let d = (c as char).to_digit(16).ok_or(Error::Json)?;
            v = (v << 4) | d;
        }
        self.pos += 4;
        Ok(v)
    }

    /// Parses the body of a string; the opening quote has been consumed.
    fn string(&mut self) -> Result<String, Error> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or(Error::Json)?;
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or(Error::Json)?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                // High surrogate: a low surrogate escape must follow.
                                self.expect(b"\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(Error::Json);
                                }
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            } else if (0xDC00..0xE000).contains(&cp) {
                                return Err(Error::Json);
                            }
                            let ch = char::from_u32(cp).ok_or(Error::Json)?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(Error::Json),
                    }
                }
                0x00..=0x1f => return Err(Error::Json),
                _ => out.push(c),
            }
        }
        // The input was `&str`, escapes produce valid UTF-8, and we copied
        // raw bytes only between quote/backslash boundaries which are ASCII,
        // so the buffer is valid UTF-8.
        String::from_utf8(out).map_err(|_| Error::Json)
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Number, Error> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(Error::Json),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return Err(Error::Json);
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(Error::Json);
            }
        }
        let text = core::str::from_utf8(&self.s[start..self.pos]).map_err(|_| Error::Json)?;
        Ok(Number(String::from(text)))
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&alloc::format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_object(obj: &Object, out: &mut String) {
    out.push('{');
    for (i, (k, v)) in obj.0.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_string(k, out);
        out.push(':');
        write_value(v, out);
    }
    out.push('}');
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.0),
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(v, out);
            }
            out.push(']');
        }
        Value::Object(o) => write_object(o, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headers() {
        let o = parse_object("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}").unwrap();
        assert_eq!(o.require_str("alg").unwrap(), "HS256");
        assert_eq!(o.require_str("typ").unwrap(), "JWT");
        let o = parse_object("{ \"kid\" : \"hs256-key\", \"alg\" : \"HS256\" }").unwrap();
        assert_eq!(o.len(), 2);
        let o = parse_object(
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
        )
        .unwrap();
        assert_eq!(
            o.get("exp"),
            Some(&Value::Number(Number::from_u64(1300819380)))
        );
        assert_eq!(
            o.get("http://example.com/is_root"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn strings_and_escapes() {
        let v = parse(r#""a\"b\\c\/d\né😀""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "a\"b\\c/d\né😀");
        assert!(parse(r#""\ud83d""#).is_err(), "lone high surrogate");
        assert!(parse(r#""\ude00""#).is_err(), "lone low surrogate");
        assert!(parse(r#""\ud83dA""#).is_err(), "bad low surrogate");
        assert!(parse("\"a\nb\"").is_err(), "raw control char");
        assert!(parse(r#""\x""#).is_err(), "unknown escape");
        assert!(parse(r#""abc"#).is_err(), "unterminated");
    }

    #[test]
    fn rejects_duplicates_and_garbage() {
        assert!(parse_object(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_object(r#"{"a":1,}"#).is_err());
        assert!(parse_object(r#"{"a":1} x"#).is_err());
        assert!(parse_object("").is_err());
        assert!(parse_object("[]").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("01").is_err());
        assert!(parse("1.").is_err());
        assert!(parse("1e").is_err());
        assert!(parse("-").is_err());
        assert!(parse("tru").is_err());
        assert!(parse("\u{feff}{}").is_err(), "BOM");
        assert!(parse("{\"a\":\u{a0}1}").is_err(), "non-JSON whitespace");
        assert_eq!(
            parse("-1.5e+3").unwrap(),
            Value::Number(Number(String::from("-1.5e+3")))
        );
    }

    #[test]
    fn depth_limit() {
        let deep: String = core::iter::repeat_n('[', MAX_DEPTH + 1)
            .chain(core::iter::repeat_n(']', MAX_DEPTH + 1))
            .collect();
        assert!(parse(&deep).is_err());
        let ok: String = core::iter::repeat_n('[', MAX_DEPTH)
            .chain(core::iter::repeat_n(']', MAX_DEPTH))
            .collect();
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn serializes_compactly() {
        let mut o = Object::new();
        o.insert_str("alg", "HS256").unwrap();
        o.insert_str("kid", "a\"b\n").unwrap();
        o.insert("n", Value::Number(Number::from_u64(7))).unwrap();
        o.insert(
            "arr",
            Value::Array(alloc::vec![Value::Null, Value::Bool(false)]),
        )
        .unwrap();
        assert!(o.insert_str("alg", "x").is_err());
        let text = o.to_json();
        assert_eq!(
            text,
            r#"{"alg":"HS256","kid":"a\"b\n","n":7,"arr":[null,false]}"#
        );
        assert_eq!(parse_object(&text).unwrap(), o);
    }

    #[test]
    fn number_accessors() {
        assert_eq!(Number(String::from("42")).as_u64(), Some(42));
        assert_eq!(Number(String::from("-1")).as_u64(), None);
        assert_eq!(Number(String::from("1.0")).as_u64(), None);
        assert_eq!(Number(String::from("99999999999999999999")).as_u64(), None);
    }
}
