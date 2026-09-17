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
percent-encoded (`%20`).

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
    # AEAD / cipher modes / MACs on block ciphers
    r"^aes_(gcm|gcm_siv|ccm|cbc_pkcs5|cmac|gmac|siv_cmac|wrap|kwp|xts)$",
    r"^aead_aes_siv_cmac$",
    r"^aegis(128L|256)$",
    r"^aria_(gcm|ccm|cbc_pkcs5|cmac|wrap|kwp)$",
    r"^camellia_(ccm|cbc_pkcs5|cmac|wrap)$",
    r"^sm4_(gcm|ccm)$",
    r"^ascon_sp800_232_aead128$",
    r"^x?chacha20_poly1305$",
    # MACs / KDFs
    r"^hmac_(sha1|sha224|sha256|sha384|sha512|sha512_224|sha512_256|sha3_224|sha3_256|sha3_384|sha3_512|sm3)$",
    r"^kmac(128|256)_no_customization$",
    r"^hkdf_sha(1|256|384|512)$",
    r"^pbkdf2_hmacsha(1|224|256|384|512)$",
    r"^pbes2_hmacsha(1|224|256|384|512)_aes_(128|192|256)$",
    # Elliptic curves
    r"^ecdsa_(secp256r1|secp384r1|secp521r1|secp256k1|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1)_(sha256|sha384|sha512|sha3_256|sha3_384|sha3_512|shake128|shake256)(_p1363)?$",
    r"^ecdsa_secp256k1_sha256_bitcoin$",
    r"^ecdh_(secp256r1|secp384r1|secp521r1|secp256k1|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1)(_ecpoint)?$",
    r"^ec_prime_order_curves$",
    r"^x(25519|448)(_asn)?$",
    r"^ed(25519|448)$",
    # RSA
    r"^rsa_signature_\d+_sha.*$",
    r"^rsa_pkcs1_\d+(_sig_gen)?$",
    # RFC 8702 SHAKE-based PSS is not implemented; every other PSS file is.
    r"^rsa_pss_(?!.*shake).*$",
    r"^rsa_oaep_\d+_.*$",
    r"^rsa_oaep_misc$",
    r"^primality$",
    # Post-quantum
    r"^mlkem_.*$",
    r"^mldsa_.*$",
]

DROP_KEY = re.compile(r"(Pem|Jwk|pem|jwk)$")


def flatten(obj, prefix, out):
    for k, v in obj.items():
        if DROP_KEY.search(k):
            continue
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            flatten(v, key + ".", out)
        elif isinstance(v, list):
            if all(isinstance(x, (str, int, bool)) for x in v):
                out.append((key, ",".join(str(x) for x in v)))
            else:
                raise ValueError(f"unsupported array under {key}")
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
