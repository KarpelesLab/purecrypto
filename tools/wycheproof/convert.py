#!/usr/bin/env python3
"""Convert Wycheproof `testvectors_v1/*.json` into the compact line format
read by `tests/wycheproof/`.

purecrypto has no JSON dependency (not even for tests), and the raw JSON is
~100 MB, so the applicable files are re-encoded into a flat, whitespace-free
`key=value` format that a few lines of Rust can parse:

    # wycheproof <file> commit=<sha> algorithm=<alg> schema=<schema>
    G <group-level fields>           -- starts a test group
    T <test-level fields>            -- one test case (belongs to the last G)

Fields are space-separated `key=value` pairs. Nested objects are flattened
with `.` (`publicKey.wx=...`); string arrays (flags) are `,`-joined. A
`comment` field, if present, is always last and runs to end of line. Keys
whose value is PEM / JWK (multi-line or structured) are dropped, as are
top-level `notes`/`header`. Everything else (hex, ints, identifiers, booleans)
is written verbatim, except that `%` and whitespace inside a value are
percent-encoded (`%20`). PEM values keep their newlines as `%0A` (a PEM/JWK
key that duplicates a sibling DER field is dropped); a value
that is a JSON object with nested objects/arrays (a JWK set) or an array of
objects is kept as compact JSON, percent-encoded.

Usage:
    convert.py <wycheproof-checkout> <out-dir>

The include list below is the set of files that purecrypto implements a
primitive for. Add to it as coverage grows.
"""
import json
import os
import re
import subprocess
import sys

INCLUDE = [
    # Every upstream file: purecrypto implements a primitive for each of them
    # (see docs/validation.md for the coverage table).
    r"^.*$",
]

def flatten(obj, prefix, out):
    for k, v in obj.items():
        # A PEM or JWK rendering of a key that is also given as DER is
        # redundant (the DER is what the harness parses); keep PEM/JWK only
        # where it is the sole form (the `*_pem` / `*_webcrypto` files).
        if (k.endswith("Pem") and k[:-3] + "Der" in obj) or (
            k.endswith("Jwk") and k[:-3] + "Der" in obj
        ):
            continue
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            if any(isinstance(x, (dict, list)) for x in v.values()):
                # Structured value (a JWK set, ...): keep it as compact JSON.
                out.append((key, json.dumps(v, separators=(",", ":"))))
            else:
                flatten(v, key + ".", out)
        elif isinstance(v, list):
            if all(isinstance(x, (str, int, bool)) for x in v):
                out.append((key, ",".join(str(x) for x in v)))
            else:
                out.append((key, json.dumps(v, separators=(",", ":"))))
        elif isinstance(v, bool):
            out.append((key, "true" if v else "false"))
        elif v is None:
            out.append((key, ""))
        else:
            out.append((key, str(v)))


def enc(v):
    """Percent-encode `%` and whitespace so a value never contains a space."""
    return "".join(f"%{ord(c):02X}" if c == "%" or c.isspace() else c for c in v)


def fields_to_line(tag, fields):
    parts = [tag]
    comment = None
    for k, v in fields:
        if k == "comment":
            comment = " ".join(v.split()) or None
            continue
        if k == "flags" and v == "":
            continue
        if "=" in k or any(c.isspace() for c in k):
            raise ValueError(f"bad key {k!r}")
        parts.append(f"{k}={enc(v)}")
    if comment is not None:
        parts.append(f"comment={comment}")
    return " ".join(parts)


def convert(path, out_path, commit):
    with open(path) as f:
        doc = json.load(f)
    name = os.path.basename(path)
    lines = [
        f"# wycheproof {name} commit={commit} algorithm={doc.get('algorithm','')} "
        f"schema={doc.get('schema','')} numberOfTests={doc.get('numberOfTests','')}"
    ]
    for group in doc["testGroups"]:
        gf = []
        flatten({k: v for k, v in group.items() if k != "tests"}, "", gf)
        lines.append(fields_to_line("G", gf))
        for t in group["tests"]:
            tf = []
            flatten(t, "", tf)
            lines.append(fields_to_line("T", tf))
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    commit = subprocess.check_output(["git", "-C", src, "rev-parse", "HEAD"]).decode().strip()
    vec = os.path.join(src, "testvectors_v1")
    os.makedirs(dst, exist_ok=True)
    pats = [re.compile(p) for p in INCLUDE]
    n = 0
    for fn in sorted(os.listdir(vec)):
        if not fn.endswith("_test.json"):
            continue
        stem = fn[: -len("_test.json")]
        if not any(p.match(stem) for p in pats):
            continue
        convert(os.path.join(vec, fn), os.path.join(dst, stem + ".txt"), commit)
        n += 1
    print(f"converted {n} files at wycheproof {commit}")


if __name__ == "__main__":
    main()
