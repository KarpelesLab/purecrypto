#!/usr/bin/env python3
"""Flattens the oracle JSON into the line format the Rust tests embed.

Usage: python3 to_kat.py vectors/gnark.json vectors/ark.json > ../../../testdata/bls12_377/kat.txt

Line kinds (all fields hex):
  g1 <k> <gnark compressed> <gnark uncompressed> <ark compressed> <ark uncompressed>
  g2 <k> <...same four...>
  pair <a> <b> <gnark GT bytes> <ark GT bytes>      (e(a·G1, b·G2))
  hash <msg> <HashToG1> <EncodeToG1> <HashToG2> <EncodeToG2>   (gnark, compressed)
  arkhash <msg> <ark G1 hash> <ark G2 hash>           (ark compressed)
  map1 <u> <MapToG1(u) compressed>
  map2 <u.c0> <u.c1> <MapToG2(u) compressed>
"""
import json
import sys

g = json.load(open(sys.argv[1]))
a = json.load(open(sys.argv[2]))
out = []
for k, pg, pa in zip(g["Scalars"], g["G1Mul"], a["G1Mul"]):
    out.append(f"g1 {k} {pg['Comp']} {pg['Raw']} {pa['Comp']} {pa['Raw']}")
for k, pg, pa in zip(g["Scalars"], g["G2Mul"], a["G2Mul"]):
    out.append(f"g2 {k} {pg['Comp']} {pg['Raw']} {pa['Comp']} {pa['Raw']}")
zero = "00" * 32
out.append(f"g1 {zero} {g['G1Inf']['Comp']} {g['G1Inf']['Raw']} {a['G1Inf']['Comp']} {a['G1Inf']['Raw']}")
out.append(f"g2 {zero} {g['G2Inf']['Comp']} {g['G2Inf']['Raw']} {a['G2Inf']['Comp']} {a['G2Inf']['Raw']}")
for pg, pa in zip(g["Pairings"], a["Pairings"]):
    out.append(f"pair {pg['A']} {pg['B']} {pg['GT']} {pa['Comp']}")
for h in g["Hashes"]:
    m = h["Msg"].encode().hex() or "-"
    out.append(f"hash {m} {h['G1Hash']['Comp']} {h['G1Encode']['Comp']} {h['G2Hash']['Comp']} {h['G2Encode']['Comp']}")
for h in a["Hashes"]:
    m = h["Msg"].encode().hex() or "-"
    out.append(f"arkhash {m} {h['G1']} {h['G2']}")
for m in g["Map1"]:
    out.append(f"map1 {m['U']} {m['Group']['Comp']}")
for m in g["Map2"]:
    out.append(f"map2 {m['U'][0]} {m['U'][1]} {m['Group']['Comp']}")
print("\n".join(out))
