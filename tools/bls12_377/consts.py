#!/usr/bin/env python3
"""Generates `src/bls12_377/constants.rs`: the BLS12-377 constants in
Montgomery form, every one derived (not transcribed) and checked.

Usage:
    python3 tools/bls12_377/consts.py \
        tools/pairing-interop/bls12-377/vectors/gnark.json \
        tools/bls12_377/iso2.json > src/bls12_377/constants.rs

Inputs:
  * the gnark-crypto vector file — only its raw `MapToCurve1/2` outputs (to
    recover the SSWU target curves E'1, E'2, which are a free design choice)
    and its `MapToG1/G2` outputs (to pick, among the six isomorphisms onto E
    and the cofactor-clearing conventions, the one gnark uses);
  * `iso2.json` from `derive_iso2.py` (the 23-isogeny kernel polynomial and
    x-map numerator, which take minutes to compute).

Everything else follows from `x = 0x8508c00000000001` and is checked before
emission: generators on the curves and of order r, the twist order and the
cofactor parities, the endomorphism eigenvalues (phi = -x^2 on G1, psi = x
on G2), the soundness of the subgroup tests, the isogenies landing on E,
SSWU reproducing gnark's raw map, the cofactor clearing reproducing gnark's
MapToG1/G2, and the final-exponentiation identity.
"""
import json
import math
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from ref377 import (  # noqa: E402
    P, R, X, H1, F2, Fp, XI, B2, G1, G2, ec_add, ec_mul, ec_neg, on_curve,
    is_square_fp, is_square_f2, sqrt_fp, sqrt_f2,
)
import polyf2 as pf  # noqa: E402
from sswu import sswu, sgn0_fp, sgn0_f2, find_z_sswu_f2  # noqa: E402

VEC = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "tools/pairing-interop/bls12-377/vectors/gnark.json"))
ISO2 = json.load(open(sys.argv[2] if len(sys.argv) > 2 else "tools/bls12_377/iso2.json"))
hx = lambda s: int(s, 16)

# ------------------------------------------------------------------ params
assert P % 4 == 1 and P % 3 == 1
TWO_ADIC_P = ((P - 1) & -(P - 1)).bit_length() - 1
assert TWO_ADIC_P == 46
Q2 = P * P
TWO_ADIC_P2 = ((Q2 - 1) & -(Q2 - 1)).bit_length() - 1
assert TWO_ADIC_P2 == 47
# G1 cofactor is even: E(Fp) has full 2-torsion (x³ + 1 splits, p ≡ 1 mod 3).
assert H1 % 2 == 0 and (P + 1 - (X + 1)) == H1 * R
# Twist order (the odd candidate) and its cofactor.
t1 = X + 1
t2 = t1 * t1 - 2 * P
f = math.isqrt((4 * P * P - t2 * t2) // 3)
H2 = None
for tt in [(t2 + 3 * f) // 2, (t2 - 3 * f) // 2, -(t2 + 3 * f) // 2, -(t2 - 3 * f) // 2]:
    n = Q2 + 1 - tt
    if n % R == 0 and (n // R) % 2 == 1 and ec_mul(n, G2) is None:
        H2 = n // R
assert H2 is not None and H2 % 2 == 1, "twist order must be odd"
assert math.gcd(H2, H1) == 1  # psi-based G2 subgroup test is sound
assert ec_mul(R, G2) is None and ec_mul(R, G1) is None
assert on_curve(G1, 0, 1) and on_curve(G2, F2(0), B2)

# ------------------------------------------------------------------ formats
def limbs(v, n):
    return [(v >> (64 * i)) & (2**64 - 1) for i in range(n)]

def fmt_limbs(v, n, indent="    "):
    return "[\n" + "".join(f"{indent}    0x{l:016x},\n" for l in limbs(v, n)) + f"{indent}]"

RP = 2**384 % P
RR = 2**256 % R

def mont_fp(v):
    return (v % P) * RP % P

def fp_const(name, v, doc, vis="pub(crate) "):
    v = v.v if isinstance(v, Fp) else v
    return f"/// {doc}\n{vis}const {name}: Fp = Fp({fmt_limbs(mont_fp(v), 6, '')});\n"

def fp_expr(v, indent):
    v = v.v if isinstance(v, Fp) else v
    return f"Fp({fmt_limbs(mont_fp(v), 6, indent)})"

def f2_expr(v, indent="    "):
    return f"Fp2::new(\n{indent}    {fp_expr(v.c0, indent + '    ')},\n{indent}    {fp_expr(v.c1, indent + '    ')},\n{indent})"

def f2_const(name, v, doc):
    return f"/// {doc}\npub(crate) const {name}: Fp2 = {f2_expr(v, '')};\n"

def raw_const(name, v, n, doc, vis="pub(crate) "):
    return f"/// {doc}\n{vis}const {name}: [u64; {n}] = {fmt_limbs(v, n, '')};\n"

def f2_array(name, vals, doc):
    body = "".join(f"    {f2_expr(v, '    ')},\n" for v in vals)
    return f"/// {doc}\npub(crate) const {name}: [Fp2; {len(vals)}] = [\n{body}];\n"

def fp_array(name, vals, doc):
    body = "".join(f"    {fp_expr(v, '    ')},\n" for v in vals)
    return f"/// {doc}\npub(crate) const {name}: [Fp; {len(vals)}] = [\n{body}];\n"

out = []
emit = out.append

# ------------------------------------------------------------------ Fp / Fr
def inv64(m):
    return (-pow(m, -1, 2**64)) % 2**64

emit("// Base field Fp.\n")
emit(raw_const("FP_MODULUS", P, 6, "The modulus `p`."))
emit(f"/// `-p^(-1) mod 2^64`.\npub(crate) const FP_INV: u64 = 0x{inv64(P):016x};\n")
emit(raw_const("FP_R", RP, 6, "`R = 2^384 mod p` (the Montgomery form of one)."))
emit(raw_const("FP_R2", RP * RP % P, 6, "`R² mod p`."))
emit(raw_const("FP_R3", RP**3 % P, 6, "`R³ mod p`."))
emit(raw_const("FP_P_MINUS_2", P - 2, 6, "`p - 2` (Fermat inversion exponent)."))
emit(raw_const("FP_P_MINUS_1_DIV_2", (P - 1) // 2, 6, "`(p - 1) / 2` (lexicographic sign threshold, Euler criterion)."))

emit("\n// Scalar field Fr.\n")
emit(raw_const("FR_MODULUS", R, 4, "The group order `r`."))
emit(f"/// `-r^(-1) mod 2^64`.\npub(crate) const FR_INV: u64 = 0x{inv64(R):016x};\n")
emit(raw_const("FR_R", RR, 4, "`R = 2^256 mod r`."))
emit(raw_const("FR_R2", RR * RR % R, 4, "`R² mod r`."))
emit(raw_const("FR_R3", RR**3 % R, 4, "`R³ mod r`."))
emit(raw_const("FR_R_MINUS_2", R - 2, 4, "`r - 2` (Fermat inversion exponent)."))

# ------------------------------------------------------------------ sqrt_ratio
def sqrt_ratio_consts(q, z, powf):
    c1 = ((q - 1) & -(q - 1)).bit_length() - 1
    c2 = (q - 1) >> c1
    c3 = (c2 - 1) // 2
    c6 = powf(z, c2)
    c7 = powf(z, (c2 + 1) // 2)
    return c1, c3, c6, c7

# G1's SSWU target curve E'1 from gnark's raw MapToCurve1 outputs.
pts1 = [(Fp(hx(m["Iso"]["X"])), Fp(hx(m["Iso"]["Y"]))) for m in VEC["Map1"] if hx(m["U"]) != 0]
(xa, ya), (xb, yb) = pts1[0], pts1[1]
ISO1_A = ((ya * ya - xa * xa * xa) - (yb * yb - xb * xb * xb)) / (xa - xb)
ISO1_B = ya * ya - xa * xa * xa - ISO1_A * xa
assert all(on_curve(pt, ISO1_A, ISO1_B) for pt in pts1)
assert ISO1_B == Fp(22)
# gnark's Z for G1 is 5 (found by reproducing MapToCurve1 below). It is a
# non-square, but fails RFC 9380 §6.6.2 criteria 3-4: the only consequence
# is that u = 0 has no valid image (both g(x1) and g(x2) = 22 are
# non-squares), which gnark maps to the identity; so do we.
Z1 = Fp(5)
assert not is_square_fp(Z1.v) and not is_square_fp(22)
for m in VEC["Map1"]:
    u = Fp(hx(m["U"]))
    if u == Fp(0):
        assert hx(m["Iso"]["X"]) == 0 and hx(m["Iso"]["Y"]) == 0
        assert m["Group"]["Comp"].startswith("c0")  # identity
        continue
    x_, y_ = sswu(u, ISO1_A, ISO1_B, Z1, sgn0_fp, lambda a: is_square_fp(a.v), lambda a: Fp(sqrt_fp(a.v)))
    assert (x_.v, y_.v) == (hx(m["Iso"]["X"]), hx(m["Iso"]["Y"])), "G1 SSWU mismatch"

# E'2 likewise; its Z is the RFC 9380 find_z_sswu choice.
pts2 = [(F2(hx(m["Iso"][0][0]), hx(m["Iso"][0][1])), F2(hx(m["Iso"][1][0]), hx(m["Iso"][1][1]))) for m in VEC["Map2"]]
(xa, ya), (xb, yb) = pts2[1], pts2[2]
ISO2_A = ((ya * ya - xa * xa * xa) - (yb * yb - xb * xb * xb)) / (xa - xb)
ISO2_B = ya * ya - xa * xa * xa - ISO2_A * xa
assert all(on_curve(pt, ISO2_A, ISO2_B) for pt in pts2)
Z2 = find_z_sswu_f2(ISO2_A, ISO2_B)
assert Z2 == F2(12, 1)
for m, pt in zip(VEC["Map2"], pts2):
    u = F2(hx(m["U"][0]), hx(m["U"][1]))
    assert sswu(u, ISO2_A, ISO2_B, Z2, sgn0_f2, is_square_f2, sqrt_f2) == pt, "G2 SSWU mismatch"

c1, c3, c6, c7 = sqrt_ratio_consts(P, Z1.v, lambda b, e: pow(b, e, P))
emit("\n// RFC 9380 sqrt_ratio (F.2.1.1) for Fp with Z = 5; also Fp::sqrt.\n")
emit(f"/// `c1`: the 2-adicity of `p - 1`.\npub(crate) const FP_SR_C1: u32 = {c1};\n")
emit(raw_const("FP_SR_C3", c3, 6, "`c3 = (c2 - 1) / 2` with `c2 = (p - 1) / 2^c1`."))
emit(fp_const("FP_SR_C6", c6, "`c6 = Z^c2`."))
emit(fp_const("FP_SR_C7", c7, "`c7 = Z^((c2 + 1) / 2)`."))
emit(fp_const("SSWU_Z1", Z1, "The SSWU `Z` for G1 (gnark-crypto's choice)."))
emit(fp_const("ISO1_A", ISO1_A, "`A'` of the G1 SSWU curve `E'1: y² = x³ + A'x + B'`."))
emit(fp_const("ISO1_B", ISO1_B, "`B' = 22` of the G1 SSWU curve."))

c1b, c3b, c6b, c7b = sqrt_ratio_consts(Q2, Z2, lambda b, e: b**e)
emit("\n// RFC 9380 sqrt_ratio for Fp2 with Z = 12 + u; also Fp2::sqrt.\n")
emit(f"/// `c1`: the 2-adicity of `p² - 1`.\npub(crate) const FP2_SR_C1: u32 = {c1b};\n")
emit(raw_const("FP2_SR_C3", c3b, 12, "`c3 = (c2 - 1) / 2` with `c2 = (p² - 1) / 2^c1`."))
emit(f2_const("FP2_SR_C6", c6b, "`c6 = Z^c2`."))
emit(f2_const("FP2_SR_C7", c7b, "`c7 = Z^((c2 + 1) / 2)`."))
emit(f2_const("SSWU_Z2", Z2, "The SSWU `Z` for G2 (RFC 9380 `find_z_sswu`)."))
emit(f2_const("ISO2_A", ISO2_A, "`A'` of the G2 SSWU curve `E'2`."))
emit(f2_const("ISO2_B", ISO2_B, "`B'` of the G2 SSWU curve `E'2`."))

# ------------------------------------------------------------------ tower
emit("\n// Tower: u² = -5, v³ = u, w² = v.\n")
FROB = [XI ** (k * (P - 1) // 6) for k in range(6)]
FROB2 = [XI ** (k * (Q2 - 1) // 6) for k in range(6)]
for k in range(1, 6):
    emit(f2_const(f"FROB_{k}", FROB[k], f"`u^({k}(p-1)/6)` (Frobenius on `w^{k}`)."))
for k in (1, 2, 4, 5):
    assert FROB2[k].c1 == 0
    emit(fp_const(f"FROB2_{k}", FROB2[k].c0, f"`u^({k}(p²-1)/6)` (in Fp)."))
assert FROB2[3] == F2(-1)

# ------------------------------------------------------------------ curves
emit("\n// Curves: E: y² = x³ + 1, E': y² = x³ + 1/u (D-type twist).\n")
emit(f2_const("B2", B2, "The twist coefficient `b' = 1/u = -u/5`."))
# 3b'·(a0 + a1 u) = (3/u)(a0 + a1 u) = 3a1 + (3a0/u)·... with 3/u = -3u/5:
#   (a0 + a1 u)(-3u/5) = 3a1 + (-3/5)a0·u.
K = Fp(-3) / Fp(5)
assert F2(0, K.v) == F2(3) * B2
emit(fp_const("MINUS_3_DIV_5", K, "`-3/5`: `3b'·(a0 + a1·u) = 3·a1 + (-3/5)·a0·u`."))
emit(fp_const("G1_X", G1[0], "x-coordinate of the G1 generator."))
emit(fp_const("G1_Y", G1[1], "y-coordinate of the G1 generator."))
emit(f2_const("G2_X", G2[0], "x-coordinate of the G2 generator."))
emit(f2_const("G2_Y", G2[1], "y-coordinate of the G2 generator."))

# GLV endomorphism phi(x, y) = (beta·x, y) acting as -x² on G1.
w3 = next(pow(g, (P - 1) // 3, P) for g in range(2, 100) if pow(g, (P - 1) // 3, P) != 1)
BETA = None
for b in (w3, w3 * w3 % P):
    if (Fp(b) * G1[0], G1[1]) == ec_mul(-X * X, G1):
        BETA = b
assert BETA is not None
emit(fp_const("BETA", BETA, "Cube root of unity with `φ(x, y) = (β·x, y) = [-x²]` on G1."))
# Soundness of phi(P) == [-x²]P as a G1 membership test: deg(phi + x²) =
# x⁴ - x² + 1 = r, so its kernel (over the closure) is exactly G1.
assert X**4 - X**2 + 1 == R

# psi on the D-type twist: psi(x, y) = (conj(x)·u^((p-1)/3), conj(y)·u^((p-1)/2)).
PSI_X = XI ** ((P - 1) // 3)
PSI_Y = XI ** ((P - 1) // 2)
PSI2_X = XI ** ((Q2 - 1) // 3)
assert PSI2_X.c1 == 0
def psi(Q):
    return None if Q is None else (Q[0].conj() * PSI_X, Q[1].conj() * PSI_Y)
def psi2(Q):
    return None if Q is None else (Q[0] * PSI2_X, -Q[1])
assert psi(G2) == ec_mul(X, G2)
assert psi(psi(G2)) == psi2(G2)
emit(f2_const("PSI_X", PSI_X, "`u^((p-1)/3)`: ψ's x-coefficient."))
emit(f2_const("PSI_Y", PSI_Y, "`u^((p-1)/2)`: ψ's y-coefficient."))
emit(fp_const("PSI2_X", PSI2_X.c0, "`u^((p²-1)/3)` (in Fp): `ψ²(x, y) = (c·x, -y)`."))

# ------------------------------------------------------------------ G1 iso
# The 2-isogeny E'1 -> E (kernel (x0, 0)), Vélu: X = x + t/(x - x0),
# Y = y·(1 - t/(x - x0)²), t = 3x0² + A', then (X, Y) -> (c·X, s·Y).
def fp_roots_cubic(a, b):
    out = []
    poly = pf.trim(([b.v, a.v, 0, 1], [0, 0, 0, 0]))
    M = pf.Modulus(poly)
    g = pf.gcd(poly, pf.sub(M.powmod(pf.X, P), pf.X))
    import random
    def split(g):
        if pf.deg(g) == 1:
            out.append(Fp(-g[0][0]))
            return
        while True:
            r = random.randrange(P)
            h = pf.Modulus(g).powmod(pf.trim(([r, 1], [0, 0])), (P - 1) // 2)
            d = pf.gcd(g, pf.sub(h, pf.ONE))
            if 0 < pf.deg(d) < pf.deg(g):
                split(d)
                split(pf.divexact(g, d))
                return
    if pf.deg(g) > 0:
        split(g)
    return out

def cube_roots_fp(a):
    # p ≡ 1 mod 3 with 3-adicity 1: brute force over the cube roots of unity.
    k = (P - 1) // 3
    e = pow(3, -1, k)
    base = pow(a, e, P)
    out = []
    for w in (1, w3, w3 * w3 % P):
        c = base * w % P
        if pow(c, 3, P) == a % P:
            out.append(c)
    return out

def heff1(Pt):
    # h_eff = 1 - x (RFC 9380 §8.8.1 for BLS12 G1).
    return ec_mul(1 - X, Pt)

iso1 = None
for x0 in fp_roots_cubic(ISO1_A, ISO1_B):
    t = 3 * x0 * x0 + ISO1_A
    if ISO1_A - 5 * t != Fp(0):
        continue
    B1c = ISO1_B - 7 * x0 * t
    inv_b = Fp(1) / B1c
    s0 = sqrt_fp(inv_b.v)
    for c in cube_roots_fp(inv_b.v):
        for s in (s0, P - s0):
            def iso(pt, c=Fp(c), s=Fp(s), x0=x0, t=t):
                X_, Y_ = pt
                d = Fp(1) / (X_ - x0)
                return (c * (X_ + t * d), s * Y_ * (1 - t * d * d))
            okall = True
            for m, pt in zip([m for m in VEC["Map1"] if hx(m["U"]) != 0], pts1):
                img = iso(pt)
                assert on_curve(img, 0, 1)
                g = heff1(img)
                if (g[0].v, g[1].v) != (hx(m["Group"]["X"]), hx(m["Group"]["Y"])):
                    okall = False
                    break
            if okall:
                assert iso1 is None, "isomorphism not unique"
                iso1 = (x0, t, Fp(c), Fp(s))
assert iso1 is not None
x0, t, c, s = iso1
# RFC 9380 form: x = x_num/x_den, y = y'·y_num/y_den, denominators monic.
#   x_num = c(x² - x0 x + t), x_den = x - x0,
#   y_num = s((x - x0)² - t), y_den = (x - x0)².
ISO1_XNUM = [c * t, c * (-x0), c]
ISO1_XDEN = [-x0, Fp(1)]
ISO1_YNUM = [s * (x0 * x0 - t), s * (-2 * x0), s]
ISO1_YDEN = [x0 * x0, -2 * x0, Fp(1)]
emit("\n// The 2-isogeny E'1 -> E (Vélu) composed with gnark's isomorphism choice.\n")
emit(fp_array("ISO1_XNUM", ISO1_XNUM, "x-numerator coefficients (constant term first)."))
emit(fp_array("ISO1_XDEN", ISO1_XDEN, "x-denominator coefficients (monic)."))
emit(fp_array("ISO1_YNUM", ISO1_YNUM, "y-numerator coefficients."))
emit(fp_array("ISO1_YDEN", ISO1_YDEN, "y-denominator coefficients (monic)."))

# ------------------------------------------------------------------ G2 iso
D = ([hx(v) for v in ISO2["D"][0]], [hx(v) for v in ISO2["D"][1]])
N = ([hx(v) for v in ISO2["N"][0]], [hx(v) for v in ISO2["N"][1]])
B2c = F2(hx(ISO2["B_codomain"][0]), hx(ISO2["B_codomain"][1]))
assert pf.deg(D) == 11 and pf.deg(N) == 23
# D divides the 23-division polynomial: re-check that the x-map lands on a
# j = 0 curve for every sample point, and that y·X'(x) satisfies it.
D2 = pf.mul(D, D)
D3 = pf.mul(D2, D)
Np = pf.derivative(N)
Dp = pf.derivative(D)
YN = pf.sub(pf.mul(Np, D), pf.scale(pf.mul(N, Dp), (2, 0)))  # y-map: y·YN/D³
ev = lambda poly, x: F2(*pf.evaluate(poly, (x.c0, x.c1)))
for pt in pts2:
    xv, yv = pt
    X_ = ev(N, xv) / ev(D2, xv)
    Y_ = yv * ev(YN, xv) / ev(D3, xv)
    assert Y_ * Y_ == X_ * X_ * X_ + B2c
target = B2 / B2c  # s² = c³ = b'/B''
sq = sqrt_f2(target)
cubes = []
for g in range(2, 200):
    ww = F2(g, 1) ** ((Q2 - 1) // 3)
    if ww != F2(1):
        break
# cube roots of target in Fp2 by brute force over a cube root and units
k3 = 0
qq = Q2 - 1
while qq % 3 == 0:
    qq //= 3
    k3 += 1
for a0 in range(0, 50):
    cand = F2(a0, 1) ** ((Q2 - 1) // 3)
    if cand != F2(1):
        unity = cand
        break

def cube_roots_f2(a):
    # Adleman-Manders-Miller-lite: q-1 = 3^k·m, gcd(3, m) = 1.
    m_ = qq
    e = pow(3, -1, m_)
    base = a ** e  # base³ = a · (a^(3e-1)), a^(3e-1) has 3-power order
    roots = []
    zg = None
    for a0 in range(0, 100):
        zz = F2(a0, 1) ** m_
        if zz ** (3 ** (k3 - 1)) != F2(1):
            zg = zz
            break
    for i in range(3**k3):
        cnd = base * zg**i
        if cnd * cnd * cnd == a:
            roots.append(cnd)
    return roots

def heff2_bp(Q):
    # Budroni–Pintore: [x² - x - 1]Q + [x - 1]ψ(Q) + ψ²(2Q).
    return ec_add(ec_add(ec_mul(X * X - X - 1, Q), ec_mul(X - 1, psi(Q))), psi2(ec_mul(2, Q)))

clear_choice = {"bp": heff2_bp, "h2": lambda Q: ec_mul(H2, Q)}
iso2 = None
for cc in cube_roots_f2(target):
    for ss in (sq, -sq):
        for cname, clr in clear_choice.items():
            ok = True
            for m, pt in zip(VEC["Map2"], pts2):
                xv, yv = pt
                X_ = cc * ev(N, xv) / ev(D2, xv)
                Y_ = ss * yv * ev(YN, xv) / ev(D3, xv)
                img = (X_, Y_)
                assert on_curve(img, F2(0), B2)
                g = clr(img)
                want = (F2(hx(m["Group"]["X"][0]), hx(m["Group"]["X"][1])), F2(hx(m["Group"]["Y"][0]), hx(m["Group"]["Y"][1])))
                if g != want:
                    ok = False
                    break
            if ok:
                assert iso2 is None, "G2 isomorphism/clearing not unique"
                iso2 = (cc, ss, cname)
assert iso2 is not None, "no G2 isomorphism/clearing reproduces gnark"
cc, ss, cname = iso2
assert cname == "bp"
coeffs = lambda poly: [F2(a0, a1) for a0, a1 in zip(*poly)]
ISO2_XNUM = [cc * v for v in coeffs(N)]
ISO2_XDEN = coeffs(pf.monic(D2))
ISO2_YNUM = [ss * v for v in coeffs(YN)]
ISO2_YDEN = coeffs(pf.monic(D3))
assert coeffs(D2)[-1] == F2(1) and coeffs(D3)[-1] == F2(1)
emit("\n// The 23-isogeny E'2 -> E' (Kohel/Vélu, see derive_iso2.py) composed with\n// gnark's isomorphism choice; cofactor clearing is Budroni–Pintore.\n")
emit(f2_array("ISO2_XNUM", ISO2_XNUM, "x-numerator coefficients (constant term first, degree 23)."))
emit(f2_array("ISO2_XDEN", ISO2_XDEN, "x-denominator coefficients (monic, degree 22)."))
emit(f2_array("ISO2_YNUM", ISO2_YNUM, "y-numerator coefficients (degree 33)."))
emit(f2_array("ISO2_YDEN", ISO2_YDEN, "y-denominator coefficients (monic, degree 33)."))

# ------------------------------------------------------------------ final exp
# 3·(p⁴ - p² + 1)/r = (x - 1)²·(x + p)·(x² + p² - 1) + 3 (Hayashida–Hayasaka–Teruya).
assert 3 * (P**4 - P**2 + 1) // R == (X - 1) ** 2 * (X + P) * (X**2 + P**2 - 1) + 3
assert (P**4 - P**2 + 1) % R == 0
# Gt membership test soundness: in the cyclotomic subgroup, f^p = f^x
# implies f^(p - x) = 1 with p - x = h1·r, and gcd(h1, Φ12(p)/r) = 1.
assert P - X == H1 * R and math.gcd(H1, (P**4 - P**2 + 1) // R) == 1

# ------------------------------------------------------------------ misc
emit("\n// Curve parameter.\n")
emit(f"/// The BLS parameter `x` (positive for BLS12-377).\npub(crate) const X: u64 = 0x{X:016x};\n")
assert H2 > 0

print("//! BLS12-377 constants, generated by `tools/bls12_377/consts.py` — do not edit.")
print("//!")
print("//! Every field constant is in Montgomery form; limbs are little-endian.")
print()
print("use super::fp::Fp;")
print("use super::fp2::Fp2;")
print()
print("\n".join(out))
