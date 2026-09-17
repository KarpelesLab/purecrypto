#!/usr/bin/env python3
"""Converts the Ethereum 2.0 BLS test vectors into `src/bls/eth_vectors.rs`.

Usage:  python3 tools/bls/eth_vectors.py <dir> > src/bls/eth_vectors.rs

`<dir>` is the extracted `bls_tests_json.tar.gz` of
https://github.com/ethereum/bls12-381-tests (release v0.1.2), i.e. the
directory holding `sign/`, `verify/`, `aggregate/`, `aggregate_verify/`,
`fast_aggregate_verify/`, `deserialization_G1/`, `deserialization_G2/` and
`hash_to_G2/`.
"""
import json, glob, os, sys

base = sys.argv[1]


def files(d):
    return sorted(glob.glob(os.path.join(base, d, "*.json")))


def name(f):
    return os.path.basename(f)[:-5]


def s(v):
    v = v[2:] if v.startswith("0x") else v
    return '"%s"' % v


def opt(v):
    return "None" if v is None else "Some(%s)" % s(v)


def lst(vs):
    return "&[" + ", ".join(s(v) for v in vs) + "]"


lines = [
    "//! Ethereum 2.0 BLS test vectors (github.com/ethereum/bls12-381-tests, v0.1.2),",
    "//! converted verbatim by `tools/bls/eth_vectors.py`. The signature cases use",
    "//! the Proof of Possession ciphersuite DST; the `hash_to_G2` cases are the",
    "//! RFC 9380 J.10.1 vectors (QUUX DST). Hex is without the `0x` prefix.",
    "",
    "#![allow(dead_code)]",
    "",
    "pub(crate) struct SignCase {",
    "    pub name: &'static str,",
    "    pub privkey: &'static str,",
    "    pub message: &'static str,",
    "    /// `None` when signing must fail (zero secret key).",
    "    pub output: Option<&'static str>,",
    "}",
    "",
    "pub(crate) struct VerifyCase {",
    "    pub name: &'static str,",
    "    pub pubkey: &'static str,",
    "    pub message: &'static str,",
    "    pub signature: &'static str,",
    "    pub output: bool,",
    "}",
    "",
    "pub(crate) struct AggregateCase {",
    "    pub name: &'static str,",
    "    pub input: &'static [&'static str],",
    "    pub output: Option<&'static str>,",
    "}",
    "",
    "pub(crate) struct AggregateVerifyCase {",
    "    pub name: &'static str,",
    "    pub pubkeys: &'static [&'static str],",
    "    pub messages: &'static [&'static str],",
    "    pub signature: &'static str,",
    "    pub output: bool,",
    "}",
    "",
    "pub(crate) struct FastAggregateVerifyCase {",
    "    pub name: &'static str,",
    "    pub pubkeys: &'static [&'static str],",
    "    pub message: &'static str,",
    "    pub signature: &'static str,",
    "    pub output: bool,",
    "}",
    "",
    "pub(crate) struct DeserializationCase {",
    "    pub name: &'static str,",
    "    pub input: &'static str,",
    "    pub output: bool,",
    "}",
    "",
    "pub(crate) struct HashToG2Case {",
    "    pub name: &'static str,",
    "    /// The ASCII message.",
    "    pub msg: &'static str,",
    "    /// `(c0, c1)` of the affine x-coordinate.",
    "    pub x: (&'static str, &'static str),",
    "    /// `(c0, c1)` of the affine y-coordinate.",
    "    pub y: (&'static str, &'static str),",
    "}",
    "",
]

lines.append("pub(crate) const SIGN: &[SignCase] = &[")
for f in files("sign"):
    d = json.load(open(f))
    lines.append(
        "    SignCase { name: %s, privkey: %s, message: %s, output: %s },"
        % ('"%s"' % name(f), s(d["input"]["privkey"]), s(d["input"]["message"]), opt(d["output"]))
    )
lines.append("];\n")

lines.append("pub(crate) const VERIFY: &[VerifyCase] = &[")
for f in files("verify"):
    d = json.load(open(f))
    i = d["input"]
    lines.append(
        "    VerifyCase { name: %s, pubkey: %s, message: %s, signature: %s, output: %s },"
        % ('"%s"' % name(f), s(i["pubkey"]), s(i["message"]), s(i["signature"]), "true" if d["output"] else "false")
    )
lines.append("];\n")

lines.append("pub(crate) const AGGREGATE: &[AggregateCase] = &[")
for f in files("aggregate"):
    d = json.load(open(f))
    lines.append(
        "    AggregateCase { name: %s, input: %s, output: %s }," % ('"%s"' % name(f), lst(d["input"]), opt(d["output"]))
    )
lines.append("];\n")

lines.append("pub(crate) const AGGREGATE_VERIFY: &[AggregateVerifyCase] = &[")
for f in files("aggregate_verify"):
    d = json.load(open(f))
    i = d["input"]
    lines.append(
        "    AggregateVerifyCase { name: %s, pubkeys: %s, messages: %s, signature: %s, output: %s },"
        % ('"%s"' % name(f), lst(i["pubkeys"]), lst(i["messages"]), s(i["signature"]), "true" if d["output"] else "false")
    )
lines.append("];\n")

lines.append("pub(crate) const FAST_AGGREGATE_VERIFY: &[FastAggregateVerifyCase] = &[")
for f in files("fast_aggregate_verify"):
    d = json.load(open(f))
    i = d["input"]
    lines.append(
        "    FastAggregateVerifyCase { name: %s, pubkeys: %s, message: %s, signature: %s, output: %s },"
        % ('"%s"' % name(f), lst(i["pubkeys"]), s(i["message"]), s(i["signature"]), "true" if d["output"] else "false")
    )
lines.append("];\n")

for group, key in (("G1", "pubkey"), ("G2", "signature")):
    lines.append("pub(crate) const DESERIALIZATION_%s: &[DeserializationCase] = &[" % group)
    for f in files("deserialization_" + group):
        d = json.load(open(f))
        lines.append(
            "    DeserializationCase { name: %s, input: %s, output: %s },"
            % ('"%s"' % name(f), s(d["input"][key]), "true" if d["output"] else "false")
        )
    lines.append("];\n")

lines.append("pub(crate) const HASH_TO_G2: &[HashToG2Case] = &[")
for f in files("hash_to_G2"):
    d = json.load(open(f))
    x = d["output"]["x"].split(",")
    y = d["output"]["y"].split(",")
    msg = d["input"]["msg"]
    assert all(32 <= ord(c) < 127 and c != '"' and c != "\\" for c in msg)
    lines.append(
        "    HashToG2Case { name: %s, msg: %s, x: (%s, %s), y: (%s, %s) },"
        % ('"%s"' % name(f), '"%s"' % msg, s(x[0]), s(x[1]), s(y[0]), s(y[1]))
    )
lines.append("];")

sys.stdout.write("\n".join(lines) + "\n")
