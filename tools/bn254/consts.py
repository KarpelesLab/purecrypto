#!/usr/bin/env python3
"""Generates `src/bn254/constants.rs`: the BN254 constants in Montgomery form.

Usage:  python3 tools/bn254/consts.py > src/bn254/constants.rs && cargo fmt

Everything is derived from the BN parameter `x = 4965661367192848881`
(`p = 36x⁴ + 36x³ + 24x² + 6x + 1`, `r = 36x⁴ + 36x³ + 18x² + 6x + 1`) with
a small affine-curve implementation, and checked before emission:

* generators on their curves and of order `r`; `E(Fp)` of prime order and the
  twist cofactor `h₂ = 2p − r` odd (so the complete `a = 0` formulas are
  exception-free on both curves, which have no 2-torsion);
* `ψ` (untwist–Frobenius–twist) acting as `p ≡ 6x² (mod r)` on `G2`, and
  `gcd(λ² − tλ + p, h₂) = 1` for `λ = 6x²`, which makes the membership test
  `ψ(Q) = [6x²]Q` exact on all of `E'(Fp2)` (no point outside `G2` passes);
* the Fuentes-Castañeda–Knapp–Rodríguez-Henríquez cofactor formula against
  a multiple of `h₂`, and its image landing in `G2`;
* the hard-part decomposition `Σ λᵢ pⁱ = 2x(6x² + 3x + 1)·(p⁴ − p² + 1)/r`;
* the RFC 9380 Shallue–van de Woestijne constants (`Z` by the Appendix H.1
  search, `c3` with `sgn0 = 0`) for both groups;
* the signed-digit form of the Miller-loop constant `6x + 2`;
* the GLV (`G1`, `φ(x, y) = (βx, y)` acting as a cube root of unity `λ`) and
  GLS (`G2`, `ψ` acting as `6x²`) lattice bases: determinant `±r`, every
  row in the kernel, and the Babai round-off bound proving the sub-scalars
  fit 127 bits (`G1`) and 64 bits (`G2`) — plus the exact integer algorithm
  of the Rust code replayed on 2000 random scalars and the edge cases.
"""

X = 4965661367192848881
p = 36 * X**4 + 36 * X**3 + 24 * X**2 + 6 * X + 1
r = 36 * X**4 + 36 * X**3 + 18 * X**2 + 6 * X + 1
t = 6 * X * X + 1  # trace of Frobenius on E(Fp)
assert p == 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47
assert r == 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
assert p + 1 - t == r
assert p % 4 == 3 and p % 6 == 1


def inv(a, m=p):
    return pow(a, -1, m)


def is_prime(n):
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        y = pow(a, d, n)
        if y in (1, n - 1):
            continue
        for _ in range(s - 1):
            y = y * y % n
            if y == n - 1:
                break
        else:
            return False
    return True


assert is_prime(p) and is_prime(r)

# ---------------------------------------------------------------- Fp2
def f2add(a, b):
    return ((a[0] + b[0]) % p, (a[1] + b[1]) % p)


def f2sub(a, b):
    return ((a[0] - b[0]) % p, (a[1] - b[1]) % p)


def f2neg(a):
    return ((-a[0]) % p, (-a[1]) % p)


def f2mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % p, (a[0] * b[1] + a[1] * b[0]) % p)


def f2inv(a):
    n = inv((a[0] * a[0] + a[1] * a[1]) % p)
    return (a[0] * n % p, (-a[1]) * n % p)


def f2pow(a, e):
    out = (1, 0)
    while e:
        if e & 1:
            out = f2mul(out, a)
        a = f2mul(a, a)
        e >>= 1
    return out


def f2conj(a):
    return (a[0], (-a[1]) % p)


def f2_is_square(a):
    n = (a[0] * a[0] + a[1] * a[1]) % p
    return n == 0 or pow(n, (p - 1) // 2, p) == 1


def f2sqrt(a):
    # Adj–Rodríguez-Henríquez Algorithm 9 (p ≡ 3 mod 4).
    a1 = f2pow(a, (p - 3) // 4)
    alpha = f2mul(f2mul(a1, a1), a)
    x0 = f2mul(a1, a)
    if alpha == (p - 1, 0):
        x = f2mul((0, 1), x0)
    else:
        b = f2pow(f2add((1, 0), alpha), (p - 1) // 2)
        x = f2mul(b, x0)
    assert f2mul(x, x) == (a[0] % p, a[1] % p)
    return x


def sgn0_fp(a):
    return a % p & 1


def sgn0_fp2(a):
    return (a[0] & 1) | ((a[0] == 0) & (a[1] & 1))


XI = (9, 1)
assert not f2_is_square(XI) and f2pow(XI, (p * p - 1) // 3) != (1, 0)

# ---------------------------------------------------------------- curves
class Curve:
    def __init__(self, ops, b):
        self.mul, self.add, self.sub, self.neg, self.inv = ops
        self.b = b

    def on_curve(self, P):
        x, y = P
        return self.mul(y, y) == self.add(self.mul(self.mul(x, x), x), self.b)

    def dbl(self, P):
        if P is None:
            return None
        x, y = P
        if y == self.zero:
            return None
        three_x2 = self.mul(self.const(3), self.mul(x, x))
        lam = self.mul(three_x2, self.inv(self.add(y, y)))
        x3 = self.sub(self.sub(self.mul(lam, lam), x), x)
        return (x3, self.sub(self.mul(lam, self.sub(x, x3)), y))

    def addp(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0]:
            return self.dbl(P) if P[1] == Q[1] else None
        lam = self.mul(self.sub(Q[1], P[1]), self.inv(self.sub(Q[0], P[0])))
        x3 = self.sub(self.sub(self.mul(lam, lam), P[0]), Q[0])
        return (x3, self.sub(self.mul(lam, self.sub(P[0], x3)), P[1]))

    def negp(self, P):
        return None if P is None else (P[0], self.neg(P[1]))

    def smul(self, k, P):
        if k < 0:
            return self.smul(-k, self.negp(P))
        out = None
        while k:
            if k & 1:
                out = self.addp(out, P)
            P = self.dbl(P)
            k >>= 1
        return out


E1 = Curve((lambda a, b: a * b % p, lambda a, b: (a + b) % p, lambda a, b: (a - b) % p,
            lambda a: (-a) % p, inv), 3)
E1.zero, E1.const = 0, (lambda k: k)
B2 = f2mul((3, 0), f2inv(XI))
E2 = Curve((f2mul, f2add, f2sub, f2neg, f2inv), B2)
E2.zero, E2.const = (0, 0), (lambda k: (k, 0))

G1 = (1, 2)
G2 = (
    (0x1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED,
     0x198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2),
    (0x12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA,
     0x090689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B),
)
assert E1.on_curve(G1) and E2.on_curve(G2)
assert E1.smul(r, G1) is None and E2.smul(r, G2) is None
# #E(Fp) = r (prime: no 2-torsion), #E'(Fp2) = r·(2p − r) with odd cofactor.
H2 = 2 * p - r
assert H2 % 2 == 1 and H2 % r != 0
# The twist order: #E'(Fp2) = p² + 1 − t₂' with the sextic-twist trace; check
# it on a random point instead of deriving it.
_probe = None
for xs in range(1, 50):
    rhs = f2add(f2mul(f2mul((xs, 1), (xs, 1)), (xs, 1)), B2)
    if f2_is_square(rhs):
        _probe = ((xs, 1), f2sqrt(rhs))
        break
assert E2.on_curve(_probe) and E2.smul(r * H2, _probe) is None
assert E2.smul(r, _probe) is not None and E2.smul(H2, _probe) is not None

# ---------------------------------------------------------------- Frobenius
GAM = [f2pow(XI, i * (p - 1) // 6) for i in range(6)]
GAM2 = [f2pow(XI, i * (p * p - 1) // 6) for i in range(6)]
assert all(g[1] == 0 for g in GAM2) and GAM2[3] == (p - 1, 0)


def psi(P):
    if P is None:
        return None
    return (f2mul(f2conj(P[0]), GAM[2]), f2mul(f2conj(P[1]), GAM[3]))


LAMBDA = 6 * X * X
assert p % r == LAMBDA % r
assert psi(G2) == E2.smul(LAMBDA, G2)
assert E2.on_curve(psi(_probe))
# ψ satisfies ψ² − tψ + p = 0 on E'(Fp2); the membership test ψ(Q) = λQ only
# accepts points whose every prime-power component has λ as an eigenvalue,
# impossible outside G2 when λ² − tλ + p shares no factor with h₂.
from math import gcd

assert gcd(LAMBDA * LAMBDA - t * LAMBDA + p, H2) == 1
assert psi(_probe) != E2.smul(LAMBDA, _probe)
_ps = psi(psi(_probe))
assert E2.addp(E2.addp(_ps, E2.negp(E2.smul(t, psi(_probe)))), E2.smul(p, _probe)) is None


# FKR cofactor clearing: [x]Q + ψ([3x]Q) + ψ²([x]Q) + ψ³(Q).
def clear_g2(Q):
    xq = E2.smul(X, Q)
    return E2.addp(E2.addp(E2.addp(xq, psi(E2.smul(3 * X, Q))), psi(psi(xq))), psi(psi(psi(Q))))


_c = clear_g2(_probe)
assert _c is not None and E2.smul(r, _c) is None

# ---------------------------------------------------------------- final exp
M_FE = 2 * X * (6 * X * X + 3 * X + 1)
L0 = 1 + 6 * X + 12 * X**2 + 12 * X**3
L1 = 4 * X + 6 * X**2 + 12 * X**3
L2 = 6 * X + 6 * X**2 + 12 * X**3
L3 = -1 + 4 * X + 6 * X**2 + 12 * X**3
assert (p**4 - p**2 + 1) % r == 0
assert L0 + L1 * p + L2 * p**2 + L3 * p**3 == M_FE * ((p**4 - p**2 + 1) // r)
assert gcd(M_FE, r) == 1

# ---------------------------------------------------------------- Miller loop
ATE = 6 * X + 2


def naf(n):
    out = []
    while n:
        if n & 1:
            d = 2 - (n % 4)
            n -= d
        else:
            d = 0
        out.append(d)
        n //= 2
    return out


ATE_NAF = naf(ATE)
assert sum(d << i for i, d in enumerate(ATE_NAF)) == ATE and ATE_NAF[-1] == 1
# The optimal ate relation 6x + 2 + p − p² + p³ ≡ 0 (mod r) behind the two
# Frobenius line terms.
assert (ATE + p - p**2 + p**3) % r == 0
# The Miller loop's incomplete addition step never meets T = ±(added point):
# inside the loop T = [m]Q with m ≥ 2 the running prefix of the digits, and
# the two closing additions add ψ(Q) = [p]Q to [6x+2]Q, then −ψ²(Q) = [−p²]Q
# to [6x+2+p]Q.
_m = 1
for d in reversed(ATE_NAF[:-1]):
    _m *= 2
    if d:
        assert _m % r not in (1, r - 1) and _m >= 2
        _m += d
assert _m == ATE
for _t, _a in ((ATE, p), (ATE + p, -(p**2))):
    assert (_t - _a) % r != 0 and (_t + _a) % r != 0 and _t % r != 0

# ---------------------------------------------------------------- GLV / GLS
# G1: φ(x, y) = (βx, y) for a cube root of unity β ∈ Fp acts on G1 as a
# cube root of unity λ (λ² + λ + 1 ≡ 0 mod r). Pick the β/λ pair the short
# basis below belongs to: k ≡ s₀ + s₁λ with (s₀, s₁) = (k, 0) − Babai.
GLV_LAMBDA = None
for _g in range(2, 100):
    _w = pow(_g, (p - 1) // 3, p)
    if _w != 1:
        break
for _beta in (_w, _w * _w % p):
    _phi = (_beta * G1[0] % p, G1[1])
    for _lam in (pow(_g2, (r - 1) // 3, r) for _g2 in range(2, 4)):
        for _l in (_lam, _lam * _lam % r):
            if _l != 1 and E1.smul(_l, G1) == _phi:
                GLV_BETA, GLV_LAMBDA = _beta, _l
assert GLV_LAMBDA is not None and (GLV_LAMBDA**2 + GLV_LAMBDA + 1) % r == 0
assert pow(GLV_BETA, 3, p) == 1 and GLV_BETA != 1
# The short GLV basis (Gauss/LLL-reduced, written in x).
GLV_BASIS = [
    [6 * X * X + 4 * X + 1, 2 * X + 1],
    [2 * X + 1, -(6 * X * X + 2 * X)],
]
# G2: ψ acts as μ = 6x² ≡ p; the four-dimensional LLL-reduced basis of
# {v : Σ vᵢμⁱ ≡ 0 (mod r)} (Galbraith–Scott shape for BN curves).
GLS_MU = LAMBDA
GLS_BASIS = [
    [2 * X + 1, 0, 2 * X, 1],
    [2 * X, X + 1, -X, X],
    [X + 1, X, X, -2 * X],
    [2 * X + 1, -X, -(X + 1), -X],
]


def _det(M):
    if len(M) == 1:
        return M[0][0]
    return sum((-1) ** j * M[0][j] * _det([row[:j] + row[j + 1:] for row in M[1:]])
               for j in range(len(M)))


# Babai round-off with fixed-point constants. For basis rows bⱼ,
# (k, 0, …) = Σ yⱼbⱼ with yⱼ = k·αⱼ/r, αⱼ = r·(B⁻¹)₀ⱼ (an integer, as
# det B = ±r). The code computes cⱼ = ±⌊(k·gⱼ + 2^(M−1)) / 2^M⌋ with
# gⱼ = round(2^M·|αⱼ|/r), so |cⱼ − yⱼ| ≤ 1/2 + k/2^(M+1) and every
# sub-scalar sᵢ = Σⱼ (yⱼ − cⱼ)·bⱼᵢ is bounded by that times Σⱼ |bⱼᵢ|.
BABAI_SHIFT = 320


def babai_consts(B, lam, digit_bits):
    n = len(B)
    assert _det(B) in (r, -r)
    for b in B:
        assert sum(e * pow(lam, i, r) for i, e in enumerate(b)) % r == 0
        assert all(abs(e) < 1 << 127 for e in b)  # fits i128
    d = _det(B)
    # Row 0 of adj(B): cofactor (j, 0) — the first column of the inverse
    # transposed, since (k, 0, …)·B⁻¹ picks row 0 of B⁻¹.
    alpha = []
    for j in range(n):
        minor = [row[1:] for i, row in enumerate(B) if i != j]
        cof = (-1) ** j * _det(minor)
        a = cof * r // d
        assert a * d == cof * r
        alpha.append(a)
    # Sanity: Σ yⱼbⱼ = (k, 0, …) for yⱼ = k·αⱼ/r.
    for i in range(n):
        assert sum(alpha[j] * B[j][i] for j in range(n)) == (r if i == 0 else 0)
    g = [(abs(a) * (1 << BABAI_SHIFT) + r // 2) // r for a in alpha]
    assert all(v < 1 << 256 for v in g)
    # |gⱼ/2^M − |αⱼ|/r| ≤ 2^-(M+1), times k < r < 2^254.
    eps = Q(1, 2) + Q(r, 1 << (BABAI_SHIFT + 1))
    for i in range(n):
        bound = eps * sum(abs(B[j][i]) for j in range(n))
        assert bound < (1 << digit_bits), (i, float(bound), digit_bits)
    # cⱼ < 2^192 (three limbs) and the intermediate products stay in 512 bits.
    assert all(((r - 1) * v + (1 << (BABAI_SHIFT - 1))) >> BABAI_SHIFT < 1 << 192 for v in g)
    return g, [a < 0 for a in alpha], alpha


def babai(k, B, g, neg):
    """The exact integer computation the Rust code performs."""
    n = len(B)
    c = [((k * gj + (1 << (BABAI_SHIFT - 1))) >> BABAI_SHIFT) * (-1 if nj else 1)
         for gj, nj in zip(g, neg)]
    return [(k if i == 0 else 0) - sum(c[j] * B[j][i] for j in range(n)) for i in range(n)]


from fractions import Fraction as Q

GLV_G, GLV_NEG, GLV_ALPHA = babai_consts(GLV_BASIS, GLV_LAMBDA, 127)
GLS_G, GLS_NEG, GLS_ALPHA = babai_consts(GLS_BASIS, GLS_MU, 64)
import random as _random

_rng = _random.Random(254)
# Edge scalars for the Rust tests: the trivial ones, the eigenvalues, the
# rounding half-way points k ≈ (c + 1/2)·r/|αⱼ| of every Babai coefficient
# (where cⱼ flips), and the random scalars with the largest sub-scalars.
EDGE = [0, 1, 2, r - 1, r - 2, (r - 1) // 2, (r + 1) // 2, GLV_LAMBDA, GLV_LAMBDA + 1,
        GLV_LAMBDA - 1, r - GLV_LAMBDA, GLS_MU, GLS_MU + 1, GLS_MU - 1, X, X * X, X**3,
        6 * X * X + 4 * X + 1, 6 * X * X + 2 * X, 2 * X + 1, (1 << 127) - 1, 1 << 127, 1 << 128,
        (1 << 64) - 1, 1 << 64, (1 << 192) + 1]
for _a in GLV_ALPHA + GLS_ALPHA:
    _cmax = (r - 1) * abs(_a) // r
    for _c in sorted({0, 1, _cmax // 2, max(_cmax - 1, 0), _cmax}):
        _h = ((2 * _c + 1) * r) // (2 * abs(_a))
        EDGE += [_h - 1, _h, _h + 1]
EDGE = sorted({k for k in EDGE if 0 <= k < r})
_worst = []
for _k in [_rng.randrange(r) for _ in range(4000)]:
    _w1 = max(abs(v) for v in babai(_k, GLV_BASIS, GLV_G, GLV_NEG))
    _w2 = max(abs(v) for v in babai(_k, GLS_BASIS, GLS_G, GLS_NEG))
    _worst.append((_w1 / 2.0**127 + _w2 / 2.0**64, _k))
_worst.sort(reverse=True)
EDGE += [k for _, k in _worst[:8]]
for _k in EDGE + [_rng.randrange(r) for _ in range(2000)]:
    _s = babai(_k, GLV_BASIS, GLV_G, GLV_NEG)
    assert (_s[0] + _s[1] * GLV_LAMBDA - _k) % r == 0 and all(abs(v) < 1 << 127 for v in _s)
    _s = babai(_k, GLS_BASIS, GLS_G, GLS_NEG)
    assert sum(v * pow(GLS_MU, i, r) for i, v in enumerate(_s)) % r == _k % r
    assert all(abs(v) < 1 << 64 for v in _s)
# The endomorphisms on a non-trivial point: k·G against the split.
_k = _rng.randrange(r)
_s = babai(_k, GLV_BASIS, GLV_G, GLV_NEG)
assert E1.addp(E1.smul(_s[0], G1), E1.smul(_s[1], (GLV_BETA * G1[0] % p, G1[1]))) \
    == E1.smul(_k, G1)
_s = babai(_k, GLS_BASIS, GLS_G, GLS_NEG)
_acc, _q = None, G2
for _v in _s:
    _acc = E2.addp(_acc, E2.smul(_v, _q))
    _q = psi(_q)
assert _acc == E2.smul(_k, G2)

# ---------------------------------------------------------------- SVDW (RFC 9380 §6.6.1)
def find_z(add, mul, neg, inv_, is_sq, const, g, zero):
    ctr = 1
    while True:
        for z in (const(ctr), neg(const(ctr))):
            gz = g(z)
            if gz == zero:
                continue
            three_z2 = mul(const(3), mul(z, z))  # A = 0
            h = neg(mul(three_z2, inv_(mul(const(4), gz))))
            if h == zero or not is_sq(h):
                continue
            if is_sq(gz) or is_sq(g(neg(mul(z, inv_(const(2)))))):
                return z
        ctr += 1


def fp_is_sq(a):
    return a % p == 0 or pow(a, (p - 1) // 2, p) == 1


g1f = lambda x: (x * x * x + 3) % p
Z1 = find_z(E1.add, E1.mul, E1.neg, inv, fp_is_sq, lambda k: k % p, g1f, 0)
g2f = lambda x: f2add(f2mul(f2mul(x, x), x), B2)
Z2 = find_z(f2add, f2mul, f2neg, f2inv, f2_is_square, lambda k: (k % p, 0), g2f, (0, 0))


def svdw_consts(Z, add, mul, neg, inv_, sqrt_, sgn0, const, g):
    gz = g(Z)
    three_z2 = mul(const(3), mul(Z, Z))
    c1 = gz
    c2 = neg(mul(Z, inv_(const(2))))
    c3 = sqrt_(neg(mul(gz, three_z2)))
    if sgn0(c3):
        c3 = neg(c3)
    c4 = neg(mul(mul(const(4), gz), inv_(three_z2)))
    return c1, c2, c3, c4


S1 = svdw_consts(Z1, E1.add, E1.mul, E1.neg, inv, lambda a: pow(a, (p + 1) // 4, p), sgn0_fp,
                 lambda k: k % p, g1f)
assert S1[2] * S1[2] % p == (-g1f(Z1) * 3 * Z1 * Z1) % p
S2 = svdw_consts(Z2, f2add, f2mul, f2neg, f2inv, f2sqrt, sgn0_fp2, lambda k: (k % p, 0), g2f)

# ------------------------------------------------------------ Montgomery emit
R256 = 1 << 256


def limbs(v, n=4):
    return [(v >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(n)]


def fmt_limbs(ls):
    return "[" + ", ".join("0x%016x" % l for l in ls) + "]"


def fp(v, name=None):
    v %= p
    s = "Fp(%s)" % fmt_limbs(limbs(v * R256 % p))
    if name is None:
        return s
    return "/// `0x%x`\npub(crate) const %s: Fp = %s;" % (v, name, s)


def fp2(v, name=None):
    s = "Fp2 { c0: %s, c1: %s }" % (fp(v[0]), fp(v[1]))
    if name is None:
        return s
    return "/// `0x%x + 0x%x·u`\npub(crate) const %s: Fp2 = %s;" % (v[0] % p, v[1] % p, name, s)


def raw(name, v, doc):
    return "/// %s\npub(crate) const %s: [u64; 4] = %s;" % (doc, name, fmt_limbs(limbs(v)))


out = []


def emit(s=""):
    out.append(s)


emit("""//! BN254 curve constants in Montgomery form.
//!
//! Generated by `tools/bn254/consts.py` from the BN parameter
//! `x = 4965661367192848881`; the script checks every value (generators
//! on-curve and of order `r`, the odd twist cofactor, `ψ` acting as `6x²`
//! with an exact membership test, the cofactor-clearing formula, the
//! final-exponentiation decomposition, the GLV/GLS lattices with their
//! Babai bounds and the RFC 9380 SVDW constants)
//! before emitting. Each field element is `value·2^256 mod p` as four
//! little-endian limbs; the doc comment on each constant gives the plain
//! value. Do not edit by hand.

use super::fp::Fp;
use super::fp2::Fp2;
""")
emit("/// The BN parameter `x` (positive).")
emit("pub(crate) const X: u64 = 0x%016x;" % X)
emit()
emit("// Fp")
emit(raw("P", p, "The base-field modulus `p`."))
emit("/// `-p^(-1) mod 2^64`.\npub(crate) const P_INV: u64 = 0x%016x;" % ((-inv(p, 1 << 64)) % (1 << 64)))
emit(raw("P_R", R256 % p, "`2^256 mod p` (Montgomery one)."))
emit(raw("P_R2", R256 * R256 % p, "`2^512 mod p`."))
emit(raw("P_R3", R256**3 % p, "`2^768 mod p`."))
emit(raw("P_MINUS_2", p - 2, "`p - 2` (Fermat inversion)."))
emit(raw("P_PLUS_1_DIV_4", (p + 1) // 4, "`(p + 1)/4` (square root)."))
emit(raw("P_MINUS_1_DIV_2", (p - 1) // 2, "`(p - 1)/2` (Legendre symbol, sign)."))
emit(raw("P3_MINUS_5_DIV_4", (3 * p - 5) // 4, "`(3p - 5)/4` (`Fp2` square root)."))
emit(fp((p + 1) // 2, "HALF"))
emit()
emit("// Fr")
emit(raw("R_MOD", r, "The group order `r`."))
emit("/// `-r^(-1) mod 2^64`.\npub(crate) const R_INV: u64 = 0x%016x;" % ((-inv(r, 1 << 64)) % (1 << 64)))
emit(raw("R_R", R256 % r, "`2^256 mod r` (Montgomery one)."))
emit(raw("R_R2", R256 * R256 % r, "`2^512 mod r`."))
emit(raw("R_R3", R256**3 % r, "`2^768 mod r`."))
emit(raw("R_MINUS_2", r - 2, "`r - 2` (Fermat inversion)."))
emit()
emit("// curves and generators")
emit(fp(3, "B1"))
emit(fp2(B2, "B2"))
emit(fp2(f2mul((3, 0), B2), "B2_3"))
emit(fp(G1[0], "G1_X"))
emit(fp(G1[1], "G1_Y"))
emit(fp2(G2[0], "G2_X"))
emit(fp2(G2[1], "G2_Y"))
emit()
emit("// Frobenius: xi^(i*(p-1)/6), i = 1..5 (xi = 9 + u)")
for i in range(1, 6):
    emit(fp2(GAM[i], "FROB_%d" % i))
emit("// p²-Frobenius: xi^(i*(p²-1)/6) for i = 1, 2, 4, 5 (all in Fp; i = 3 gives -1)")
for i in (1, 2, 4, 5):
    emit(fp(GAM2[i][0], "FROB2_%d" % i))
emit()
emit("/// Signed binary digits of the Miller-loop constant `6x + 2`, least")
emit("/// significant first (the top digit, 1, is implicit in `T = Q`).")
emit("pub(crate) const ATE_NAF: [i8; %d] = [%s];" % (len(ATE_NAF), ", ".join(str(d) for d in ATE_NAF)))
emit()
emit("// GLV (G1) and GLS (G2) scalar decomposition")
emit(fp(GLV_BETA, "GLV_BETA"))
emit("/// `φ(x, y) = (βx, y)` acts on `G1` as `λ = 0x%x`." % GLV_LAMBDA)


def babai_emit(prefix, B, g, neg, what):
    n = len(B)
    emit("/// The reduced lattice basis of %s (rows), entries in `x`." % what)
    emit("pub(crate) const %s_BASIS: [[i128; %d]; %d] = [%s];" % (
        prefix, n, n, ", ".join("[" + ", ".join("%d" % e for e in b) + "]" for b in B)))
    emit("/// Babai round-off constants `round(2^%d·|αⱼ|/r)`." % BABAI_SHIFT)
    emit("pub(crate) const %s_G: [[u64; 4]; %d] = [%s];" % (
        prefix, n, ", ".join(fmt_limbs(limbs(v)) for v in g)))
    emit("/// Signs of the `αⱼ` (`true` = negative).")
    emit("pub(crate) const %s_NEG: [bool; %d] = [%s];" % (
        prefix, n, ", ".join("true" if v else "false" for v in neg)))


babai_emit("GLV", GLV_BASIS, GLV_G, GLV_NEG, "`{(s₀, s₁) : s₀ + s₁λ ≡ 0}`")
babai_emit("GLS", GLS_BASIS, GLS_G, GLS_NEG, "`{s : Σ sᵢ(6x²)ⁱ ≡ 0}`")
emit("/// Test scalars for the GLV/GLS splits: the Babai rounding half-way")
emit("/// points of every coefficient, the eigenvalues and the random scalars")
emit("/// with the largest sub-scalars (canonical little-endian limbs).")
emit("#[cfg(test)]")
emit("pub(crate) const BABAI_EDGE_SCALARS: [[u64; 4]; %d] = [%s];" % (
    len(EDGE), ", ".join(fmt_limbs(limbs(k)) for k in EDGE)))
emit()
emit("// RFC 9380 Shallue–van de Woestijne, G1 (A = 0, B = 3)")
emit(fp(Z1, "SVDW1_Z"))
for i, c in enumerate(S1):
    emit(fp(c, "SVDW1_C%d" % (i + 1)))
emit("// RFC 9380 Shallue–van de Woestijne, G2 (A = 0, B = 3/(9 + u))")
emit(fp2(Z2, "SVDW2_Z"))
for i, c in enumerate(S2):
    emit(fp2(c, "SVDW2_C%d" % (i + 1)))
print("\n".join(out))
