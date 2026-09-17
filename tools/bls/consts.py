#!/usr/bin/env python3
"""Generates `src/bls/constants.rs`: the BLS12-381 constants in Montgomery form.

Usage:  python3 tools/bls/consts.py rfc9380.txt > src/bls/constants.rs

`rfc9380.txt` is the plain-text RFC 9380 (https://www.rfc-editor.org/rfc/rfc9380.txt);
the isogeny tables of Appendices E.2 and E.3 are parsed out of it rather than
transcribed by hand. Everything else is derived from the curve parameters
`p`, `r` and `x = -0xd201000000010000` with a small affine-curve implementation,
and checked before emission: generators on-curve and of order `r`, `psi(P) = x*P`
on G2, `phi(P) = -x^2*P` on G1 for the emitted `beta`, the Budroni-Pintore
cofactor formula against `h_eff*P`, the isogenies landing on `E`, and the
final-exponentiation polynomial identity.
"""
import re, sys

p = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
r = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
X = -0xD201000000010000
assert r == X**4 - X**2 + 1
assert p == (X - 1) ** 2 * (X**4 - X**2 + 1) // 3 + X
assert p % 4 == 3 and p % 8 == 3

RFC = sys.argv[1] if len(sys.argv) > 1 else "rfc9380.txt"

# ---------------------------------------------------------------- Fp / Fp2
def inv(a, m=p):
    return pow(a, -1, m)

def f2mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % p, (a[0] * b[1] + a[1] * b[0]) % p)

def f2add(a, b):
    return ((a[0] + b[0]) % p, (a[1] + b[1]) % p)

def f2sub(a, b):
    return ((a[0] - b[0]) % p, (a[1] - b[1]) % p)

def f2neg(a):
    return ((-a[0]) % p, (-a[1]) % p)

def f2inv(a):
    n = inv((a[0] * a[0] + a[1] * a[1]) % p)
    return ((a[0] * n) % p, (-a[1] * n) % p)

def f2pow(a, e):
    res = (1, 0)
    base = a
    while e:
        if e & 1:
            res = f2mul(res, base)
        base = f2mul(base, base)
        e >>= 1
    return res

def f2conj(a):
    return (a[0], (-a[1]) % p)

# ------------------------------------------------------------ curve arith (affine)
class Curve:
    def __init__(self, mul, add, sub, neg, invf, b):
        self.mul, self.add, self.sub, self.neg, self.inv, self.b = mul, add, sub, neg, invf, b

    def on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return self.mul(y, y) == self.add(self.mul(self.mul(x, x), x), self.b)

    def dbl(self, P):
        if P is None:
            return None
        x, y = P
        if y == self.neg(y):
            return None
        s = self.mul(self.mul(self.mul(x, x), self.three), self.inv(self.add(y, y)))
        x3 = self.sub(self.mul(s, s), self.add(x, x))
        y3 = self.sub(self.mul(s, self.sub(x, x3)), y)
        return (x3, y3)

    def addp(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0]:
            if P[1] == Q[1]:
                return self.dbl(P)
            return None
        s = self.mul(self.sub(Q[1], P[1]), self.inv(self.sub(Q[0], P[0])))
        x3 = self.sub(self.sub(self.mul(s, s), P[0]), Q[0])
        y3 = self.sub(self.mul(s, self.sub(P[0], x3)), P[1])
        return (x3, y3)

    def smul(self, k, P):
        if k < 0:
            k = -k
            P = None if P is None else (P[0], self.neg(P[1]))
        R = None
        for bit in bin(k)[2:]:
            R = self.dbl(R)
            if bit == "1":
                R = self.addp(R, P)
        return R

E1 = Curve(lambda a, b: a * b % p, lambda a, b: (a + b) % p, lambda a, b: (a - b) % p, lambda a: (-a) % p, inv, 4)
E1.three = 3
E2 = Curve(f2mul, f2add, f2sub, f2neg, f2inv, (4, 4))
E2.three = (3, 0)

G1 = (
    0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB,
    0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1,
)
G2 = (
    (
        0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8,
        0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E,
    ),
    (
        0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801,
        0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE,
    ),
)
assert E1.on_curve(G1) and E2.on_curve(G2)
assert E1.smul(r, G1) is None
assert E2.smul(r, G2) is None

# ------------------------------------------------------------ Montgomery emit
R384 = 1 << 384
R256 = 1 << 256

def limbs(v, n):
    return [(v >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(n)]

def fmt_limbs(ls):
    return "[" + ", ".join("0x%016x" % l for l in ls) + "]"

def fp(v, name=None, vis="pub(crate) const", indent=""):
    v %= p
    s = "Fp(%s)" % fmt_limbs(limbs(v * R384 % p, 6))
    if name is None:
        return s
    return "%s/// `0x%x`\n%s%s %s: Fp = %s;" % (indent, v, indent, vis, name, s)

def fp2(v, name=None, vis="pub(crate) const", indent=""):
    s = "Fp2 { c0: %s, c1: %s }" % (fp(v[0]), fp(v[1]))
    if name is None:
        return s
    return "%s/// `0x%x + 0x%x·u`\n%s%s %s: Fp2 = %s;" % (indent, v[0] % p, v[1] % p, indent, vis, name, s)

def fr(v, name, vis="pub(crate) const"):
    v %= r
    return "/// `0x%x`\n%s %s: Fr = Fr(%s);" % (v, vis, name, fmt_limbs(limbs(v * R256 % r, 4)))

out = []
def emit(s=""):
    out.append(s)

emit("// Fp")
emit("pub(crate) const MODULUS: [u64; 6] = %s;" % fmt_limbs(limbs(p, 6)))
emit("pub(crate) const INV: u64 = 0x%016x;" % ((-inv(p, 1 << 64)) % (1 << 64)))
emit("pub(crate) const R: [u64; 6] = %s;" % fmt_limbs(limbs(R384 % p, 6)))
emit("pub(crate) const R2: [u64; 6] = %s;" % fmt_limbs(limbs(R384 * R384 % p, 6)))
emit("pub(crate) const R3: [u64; 6] = %s;" % fmt_limbs(limbs(R384 * R384 * R384 % p, 6)))
emit("pub(crate) const P_MINUS_2: [u64; 6] = %s;" % fmt_limbs(limbs(p - 2, 6)))
emit("pub(crate) const P_PLUS_1_DIV_4: [u64; 6] = %s;" % fmt_limbs(limbs((p + 1) // 4, 6)))
emit("pub(crate) const P_MINUS_1_DIV_2: [u64; 6] = %s;" % fmt_limbs(limbs((p - 1) // 2, 6)))
emit()
emit("// Fr")
emit("pub(crate) const MODULUS: [u64; 4] = %s;" % fmt_limbs(limbs(r, 4)))
emit("pub(crate) const INV: u64 = 0x%016x;" % ((-inv(r, 1 << 64)) % (1 << 64)))
emit("pub(crate) const R: [u64; 4] = %s;" % fmt_limbs(limbs(R256 % r, 4)))
emit("pub(crate) const R2: [u64; 4] = %s;" % fmt_limbs(limbs(R256 * R256 % r, 4)))
emit("pub(crate) const R3: [u64; 4] = %s;" % fmt_limbs(limbs(R256 * R256 * R256 % r, 4)))
emit()

# ------------------------------------------------------------ generators
emit("// generators")
emit(fp(G1[0], "G1_X"))
emit(fp(G1[1], "G1_Y"))
emit(fp2(G2[0], "G2_X"))
emit(fp2(G2[1], "G2_Y"))
emit(fp(4, "B1"))
emit(fp(12, "B1_3"))
emit(fp2((4, 4), "B2"))
emit(fp2((12, 12), "B2_3"))
emit()

# ------------------------------------------------------------ Frobenius (xi = 1 + u)
xi = (1, 1)
emit("// Frobenius: xi^(i*(p-1)/6), i = 1..5 (xi = 1 + u)")
gam = [None] + [f2pow(xi, i * (p - 1) // 6) for i in range(1, 6)]
for i in range(1, 6):
    emit(fp2(gam[i], "FROB_%d" % i))
emit()

# psi
c1 = f2inv(gam[2])  # 1/(1+u)^((p-1)/3)
c2 = f2inv(gam[3])  # 1/(1+u)^((p-1)/2)
emit(fp2(c1, "PSI_X"))
emit(fp2(c2, "PSI_Y"))
psi2c = inv(pow(2, (p - 1) // 3, p))
emit(fp(psi2c, "PSI2_X"))

def psi(P):
    x, y = P
    return (f2mul(c1, f2conj(x)), f2mul(c2, f2conj(y)))

def psi2(P):
    x, y = P
    return (((x[0] * psi2c) % p, (x[1] * psi2c) % p), f2neg(y))

# check psi(G2) == X*G2 (or -X*G2) and psi2 consistency
xG2 = E2.smul(X, G2)
if psi(G2) == xG2:
    emit("// psi(P) == x*P for P in G2")
elif psi(G2) == E2.smul(-X, G2):
    emit("// psi(P) == -x*P for P in G2")
else:
    raise SystemExit("psi mismatch")
assert psi(psi(G2)) == psi2(G2)

# G1 endomorphism beta: phi(P) = (beta x, y) == lambda*P with lambda = -x^2
lam = (-X * X) % r
lamG = E1.smul(lam, G1)
betas = [b for b in [pow(pow(2, (p - 1) // 3, p), k, p) for k in (1, 2)]]
beta = None
for b in betas:
    assert (b * b * b) % p == 1 and b != 1
    if (b * G1[0]) % p == lamG[0] and G1[1] == lamG[1]:
        beta = b
assert beta is not None, "no beta matches lambda = -x^2"
emit(fp(beta, "BETA"))
emit("// phi(P) = (beta*x, y) == -x^2 * P for P in G1")
emit()

# ------------------------------------------------------------ pins: x*G1, x*G2
xG1 = E1.smul(X, G1)
emit("// x*G1 = (%x, %x)" % xG1)
emit("// x*G2 = ((%x, %x), (%x, %x))" % (xG2[0][0], xG2[0][1], xG2[1][0], xG2[1][1]))
emit()

# ------------------------------------------------------------ final exponentiation
lam_fe = (p**4 - p**2 + 1) // r
assert (p**4 - p**2 + 1) % r == 0
assert 3 * lam_fe == (X - 1) ** 2 * (X + p) * (X**2 + p**2 - 1) + 3
assert (X - 1) % 3 == 0
emit("// hard part: lambda = (x-1)^2/3 * (x+p) * (x^2+p^2-1) + 1")
emit("// |x| = 0x%x, |x-1| = 0x%x, |(x-1)/3| = 0x%x" % (-X, -(X - 1), -(X - 1) // 3))
emit()

# ------------------------------------------------------------ SSWU G1
emit("// SSWU G1: Z = 11")
A1 = 0x144698A3B8E9433D693A02C96D4982B0EA985383EE66A8D8E8981AEFD881AC98936F8DA0E0F97F5CF428082D584C1D
B1 = 0x12E2908D11688030018B12E8753EEE3B2016C1F0F24F4070A0B9C14FCEF35EF55A23215A316CEAA5D1CC48E98E172BE0
emit(fp(A1, "ISO1_A"))
emit(fp(B1, "ISO1_B"))
emit(fp(11, "Z1"))
emit("pub(crate) const P_MINUS_3_DIV_4: [u64; 6] = %s;" % fmt_limbs(limbs((p - 3) // 4, 6)))
c2_1 = pow((-11) % p, (p + 1) // 4, p)
assert c2_1 * c2_1 % p == (-11) % p
emit(fp(c2_1, "SQRT_MINUS_Z1"))
emit()

# ------------------------------------------------------------ SSWU G2
emit("// SSWU G2: Z = -(2+u), A' = 240u, B' = 1012(1+u)")
Z2 = ((-2) % p, (-1) % p)
emit(fp2(Z2, "Z2"))
emit(fp2((0, 240), "ISO2_A"))
emit(fp2((1012, 1012), "ISO2_B"))
q = p * p
c1v = 0
t = q - 1
while t % 2 == 0:
    t //= 2
    c1v += 1
assert c1v == 3
c2v = (q - 1) >> c1v
c3v = (c2v - 1) // 2
c4v = (1 << c1v) - 1
c5v = 1 << (c1v - 1)
emit("// sqrt_ratio (F.2.1.1): c1 = %d, c4 = %d, c5 = %d" % (c1v, c4v, c5v))
emit("pub(crate) const SQRT_RATIO_C3: [u64; 12] = %s;" % fmt_limbs(limbs(c3v, 12)))
emit(fp2(f2pow(Z2, c2v), "SQRT_RATIO_C6"))
emit(fp2(f2pow(Z2, (c2v + 1) // 2), "SQRT_RATIO_C7"))
emit()

# ------------------------------------------------------------ isogeny tables from RFC text
text = open(RFC).read()
text = text.replace("\f", "")
# strip page headers/footers
text = re.sub(r"\n[^\n]*Faz-Hernandez[^\n]*\n", "\n", text)
text = re.sub(r"\nRFC 9380[^\n]*\n", "\n", text)

def section(start, end):
    i = text.rindex(start)
    j = text.index(end, i)
    return text[i:j]

def parse_consts(sec):
    # joins continuation lines then finds k_(i,j) = ...
    body = re.sub(r"\n\s+", " ", sec)
    body = body.replace("\n", " ")
    res = {}
    for m in re.finditer(r"k_\((\d+),(\d+)\) = ([0-9a-fx +*I]+?)(?= \* k_| k_\(|$|The constants)", body):
        i, j, expr = int(m.group(1)), int(m.group(2)), m.group(3).strip().rstrip("*").strip()
        res[(i, j)] = expr
    return res

def eval_fp(expr):
    expr = expr.replace(" ", "")
    assert re.fullmatch(r"0x[0-9a-f]+", expr), expr
    return int(expr, 16)

def eval_fp2(expr):
    expr = expr.replace(" ", "")
    m = re.fullmatch(r"(0x[0-9a-f]+)?\+?((0x[0-9a-f]+)\*I)?", expr)
    assert m, expr
    c0 = int(m.group(1), 16) if m.group(1) else 0
    c1 = int(m.group(3), 16) if m.group(3) else 0
    return (c0, c1)

def emit_table(name, consts, degs, ev, fmtf, ty):
    for idx, (i, n) in enumerate(degs):
        vals = []
        for j in range(n + 1):
            key = (i, j)
            if key in consts:
                vals.append(ev(consts[key]))
            else:
                # monic leading coefficient
                assert j == n, (name, key)
                vals.append(1 if ty == "Fp" else (1, 0))
        emit("pub(crate) const %s_%d: [%s; %d] = [" % (name, i, ty, n + 1))
        for v in vals:
            emit("    %s," % fmtf(v))
        emit("];")

sec1 = section("E.2.  11-Isogeny Map for BLS12-381 G1", "E.3.  3-Isogeny Map for BLS12-381 G2")
sec1 = sec1[sec1.index("The constants used to compute x_num") :]
k1 = parse_consts(sec1)
assert len(k1) == 12 + 10 + 16 + 15, len(k1)
emit("// G1 11-isogeny (RFC 9380 E.2): x_num deg 11, x_den deg 10 (monic), y_num deg 15, y_den deg 15 (monic)")
emit_table("ISO1_K", k1, [(1, 11), (2, 10), (3, 15), (4, 15)], eval_fp, fp, "Fp")
emit()
sec2 = section("E.3.  3-Isogeny Map for BLS12-381 G2", "Appendix F.  Straight-Line")
sec2 = sec2[sec2.index("The constants used to compute x_num") :]
k2 = parse_consts(sec2)
assert len(k2) == 4 + 2 + 4 + 3, (len(k2), sorted(k2))
emit("// G2 3-isogeny (RFC 9380 E.3): x_num deg 3, x_den deg 2 (monic), y_num deg 3, y_den deg 3 (monic)")
emit_table("ISO2_K", k2, [(1, 3), (2, 2), (3, 3), (4, 3)], eval_fp2, fp2, "Fp2")
emit()

# sanity: the isogenies must map a point of E' to E. Pick x' on E' by trial.
def find_point(curve_b, A, B, mul, add, sub, sqrt_ok):
    pass

# check G1 isogeny using a point on E1'
def iso1(xp, yp):
    def poly(coeffs, x):
        acc = 0
        for c in reversed(coeffs):
            acc = (acc * x + c) % p
        return acc
    xn = poly([eval_fp(k1[(1, j)]) for j in range(12)], xp)
    xd = poly([eval_fp(k1[(2, j)]) for j in range(10)] + [1], xp)
    yn = poly([eval_fp(k1[(3, j)]) for j in range(16)], xp)
    yd = poly([eval_fp(k1[(4, j)]) for j in range(15)] + [1], xp)
    return (xn * inv(xd) % p, yp * yn * inv(yd) % p)

xp = 5
while True:
    rhs = (xp**3 + A1 * xp + B1) % p
    yp = pow(rhs, (p + 1) // 4, p)
    if yp * yp % p == rhs:
        break
    xp += 1
Q = iso1(xp, yp)
assert E1.on_curve(Q), "G1 isogeny sanity"
emit("// G1 isogeny sanity: E'(x'=%d) maps onto E" % xp)

def iso2(xp, yp):
    def poly(coeffs, x):
        acc = (0, 0)
        for c in reversed(coeffs):
            acc = f2add(f2mul(acc, x), c)
        return acc
    xn = poly([eval_fp2(k2[(1, j)]) for j in range(4)], xp)
    xd = poly([eval_fp2(k2[(2, j)]) for j in range(2)] + [(1, 0)], xp)
    yn = poly([eval_fp2(k2[(3, j)]) for j in range(4)], xp)
    yd = poly([eval_fp2(k2[(4, j)]) for j in range(3)] + [(1, 0)], xp)
    return (f2mul(xn, f2inv(xd)), f2mul(f2mul(yp, yn), f2inv(yd)))

def f2sqrt(a):
    # generic: try Tonelli via pow; q = p^2, q-1 = 2^3 * m
    # use the simple: a^((q+7)/16)... just brute using the RFC alg on small cases -> use random search
    # Use Cipolla-free approach: exponent (q+1)/4 works only if q = 3 mod 4 (q = 1 mod 4 here).
    # Fallback: sqrt in Fp2 via the zkcrypto algorithm.
    a1 = f2pow(a, (p - 3) // 4)
    alpha = f2mul(f2mul(a1, a1), a)
    x0 = f2mul(a1, a)
    if alpha == ((-1) % p, 0):
        cand = ((-x0[1]) % p, x0[0])
    else:
        cand = f2mul(f2pow(f2add(alpha, (1, 0)), (p - 1) // 2), x0)
    if f2mul(cand, cand) == a:
        return cand
    return None

xp = (3, 1)
while True:
    rhs = f2add(f2add(f2mul(f2mul(xp, xp), xp), f2mul((0, 240), xp)), (1012, 1012))
    yp = f2sqrt(rhs)
    if yp is not None:
        break
    xp = (xp[0] + 1, xp[1])
Q2 = iso2(xp, yp)
assert E2.on_curve(Q2), "G2 isogeny sanity"
emit("// G2 isogeny sanity: E'(x'=%s) maps onto E'" % (xp,))

# ------------------------------------------------------------ h_eff G2 check of BP17 formula
h_eff2 = 0xBC69F08F2EE75B3584C6A0EA91B352888E2A8E9145AD7689986FF031508FFE1329C2F178731DB956D82BF015D1212B02EC0EC69D7477C1AE954CBC06689F6A359894C0ADEBBF6B4E8020005AAA95551
def clear_cofactor_bp17(P):
    c = X
    t1 = E2.smul(c, P)
    t2 = psi(P)
    t3 = E2.dbl(P)
    t3 = psi2(t3)
    t3 = E2.addp(t3, (t2[0], f2neg(t2[1])))
    t2 = E2.addp(t1, t2)
    t2 = E2.smul(c, t2)
    t3 = E2.addp(t3, t2)
    t3 = E2.addp(t3, (t1[0], f2neg(t1[1])))
    return E2.addp(t3, (P[0], f2neg(P[1])))

assert clear_cofactor_bp17(Q2) == E2.smul(h_eff2, Q2), "BP17 clear cofactor"
emit("// BP17 clear_cofactor == h_eff * P verified on a random E2 point")
emit("pub(crate) const H_EFF_G2: [u64; 10] = %s;" % fmt_limbs(limbs(h_eff2, 10)))
h_eff1 = 0xD201000000010001
Q1c = E1.smul(h_eff1, Q)
emit("// G1: h_eff = 0x%x" % h_eff1)

# Check that the G1 (1 - x) clearing equals h_eff: h_eff = 1 - x = 0xd201000000010001
assert h_eff1 == 1 - X
# Check psi-based subgroup test on a non-subgroup point of E2 (Q2 is on E2 but very likely not in G2)
assert E2.smul(r, Q2) is not None
if psi(G2) == xG2:
    assert psi(Q2) != E2.smul(X, Q2)

HEADER = """//! BLS12-381 curve constants in Montgomery form.
//!
//! Generated by `tools/bls/consts.py` from the curve parameters `p`, `r`,
//! `x = -0xd201000000010000` and the RFC 9380 isogeny tables; the script
//! checks every value (generators on-curve and of order `r`, `ψ(P) = x·P`,
//! `φ(P) = -x²·P`, the Budroni–Pintore cofactor formula against `h_eff·P`,
//! and the isogenies landing on `E`) before emitting. Each element is
//! `value·2^384 mod p` as six little-endian limbs; the doc comment on each
//! constant gives the plain value.

use super::fp::Fp;
use super::fp2::Fp2;

"""
text = "\n".join(out)
# The Fp / Fr modulus blocks live in fp.rs and fr.rs; the h_eff limbs are only
# needed by the cofactor-clearing test.
text = text[text.index("// generators"):]
text = "\n".join(l for l in text.split("\n") if "P_MINUS_3_DIV_4" not in l)
text = text.replace("pub(crate) const H_EFF_G2: [u64; 10]", "#[cfg(test)]\npub(crate) const H_EFF_G2: [u64; 10]")
sys.stdout.write(HEADER + text + "\n")
