#!/usr/bin/env python3
"""draft-irtf-cfrg-bls-signature-05 KeyGen (§2.3) for BN254 and BLS12-377.

Written from the draft's pseudocode with the standard library only (hmac,
hashlib), independently of purecrypto's Rust code. Prints one JSON object per
line: {"curve", "ikm", "key_info", "sk"} (hex), which `gnark/main.go` then
extends with public keys and signatures.

    python3 keygen.py > vectors/keygen.jsonl
"""
import hashlib
import hmac
import json

R = {
    "bn254": 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001,
    "bls12-377": 0x12AB655E9A2CA55660B44D1E5C37B00159AA76FED00000010A11800000000001,
}


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def keygen(r, ikm, key_info=b""):
    assert len(ikm) >= 32
    L = -(-3 * r.bit_length() // 16)  # ceil((3 * ceil(log2(r))) / 16)
    assert L == 48
    salt = b"BLS-SIG-KEYGEN-SALT-"
    sk = 0
    while sk == 0:
        salt = hashlib.sha256(salt).digest()
        prk = hkdf_extract(salt, ikm + b"\x00")
        okm = hkdf_expand(prk, key_info + L.to_bytes(2, "big"), L)
        sk = int.from_bytes(okm, "big") % r
    return sk


CASES = [
    (bytes(32), b""),
    (bytes(range(32)), b""),
    (bytes.fromhex("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00"), b""),
    (bytes.fromhex("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"), b""),
    (b"an IKM of at least thirty-two bytes!", b"purecrypto key_info"),
    (bytes([0xA5]) * 64, b"\x01\x02\x03"),
]

if __name__ == "__main__":
    for curve, r in R.items():
        for ikm, info in CASES:
            sk = keygen(r, ikm, info)
            print(json.dumps({
                "curve": curve,
                "ikm": ikm.hex(),
                "key_info": info.hex(),
                "sk": sk.to_bytes(32, "big").hex(),
            }))
