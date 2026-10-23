"""Reference arithmetic for BLS12-377 (plain Python integers, no dependencies).

Used by `consts.py` (constant generation + self-checks) and by the
derivation notes in `tools/pairing-interop/bls12-377/README.md`. Nothing
here is constant time; it is a specification aid, not an implementation.
"""
import random

X = 0x8508C00000000001
P = (X - 1) ** 2 * (X**4 - X**2 + 1) // 3 + X
R = X**4 - X**2 + 1
assert P == 0x01AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000001
assert R == 0x12AB655E9A2CA55660B44D1E5C37B00159AA76FED00000010A11800000000001
H1 = (X - 1) ** 2 // 3  # G1 cofactor (even!)
BETA_NR = -5 % P  # u² = -5


def inv(a, m=P):
    return pow(a, -1, m)


# --------------------------------------------------------------------- Fp2
class F2:
    """c0 + c1·u with u² = -5."""

    __slots__ = ("c0", "c1")

    def __init__(self, c0, c1=0):
        self.c0 = c0 % P
        self.c1 = c1 % P

    def __add__(s, o):
        o = f2(o)
        return F2(s.c0 + o.c0, s.c1 + o.c1)

    __radd__ = __add__

    def __sub__(s, o):
        o = f2(o)
        return F2(s.c0 - o.c0, s.c1 - o.c1)

    def __rsub__(s, o):
        return f2(o) - s

    def __neg__(s):
        return F2(-s.c0, -s.c1)

    def __mul__(s, o):
        o = f2(o)
        return F2(s.c0 * o.c0 - 5 * s.c1 * o.c1, s.c0 * o.c1 + s.c1 * o.c0)

    __rmul__ = __mul__

    def __eq__(s, o):
        o = f2(o)
        return s.c0 == o.c0 and s.c1 == o.c1

    def __hash__(s):
        return hash((s.c0, s.c1))

    def conj(s):
        return F2(s.c0, -s.c1)

    def norm(s):
        return (s.c0 * s.c0 + 5 * s.c1 * s.c1) % P

    def inv(s):
        n = inv(s.norm())
        return F2(s.c0 * n, -s.c1 * n)

    def __truediv__(s, o):
        return s * f2(o).inv()

    def __pow__(s, e):
        r = F2(1)
        b = s
        if e < 0:
            b, e = b.inv(), -e
        while e:
            if e & 1:
                r = r * b
            b = b * b
            e >>= 1
        return r

    def is_zero(s):
        return s.c0 == 0 and s.c1 == 0

    def __repr__(s):
        return f"F2({hex(s.c0)}, {hex(s.c1)})"


def f2(a):
    return a if isinstance(a, F2) else F2(a)


Q2 = P * P


def is_square_f2(a):
    return a.is_zero() or a ** ((Q2 - 1) // 2) == F2(1)


def is_square_fp(a):
    a %= P
    return a == 0 or pow(a, (P - 1) // 2, P) == 1


def sqrt_generic(a, q, one, mul, powf, nonres):
    """Tonelli-Shanks (variable time; reference only)."""
    s, qq = 0, q - 1
    while qq % 2 == 0:
        qq //= 2
        s += 1
    z = powf(nonres, qq)
    t = powf(a, qq)
    r = powf(a, (qq + 1) // 2)
    m = s
    while t != one:
        i, t2 = 0, t
        while t2 != one:
            t2 = mul(t2, t2)
            i += 1
        if i == m:
            return None
        b = powf(z, 1 << (m - i - 1))
        m, z = i, mul(b, b)
        t, r = mul(t, z), mul(r, b)
    return r


FP_NONRES = next(c for c in range(2, 100) if not is_square_fp(c))


def sqrt_fp(a):
    a %= P
    if a == 0:
        return 0
    if not is_square_fp(a):
        return None
    return sqrt_generic(a, P, 1, lambda x, y: x * y % P, lambda b, e: pow(b, e, P), FP_NONRES)


F2_NONRES = next(F2(a, 1) for a in range(0, 100) if not is_square_f2(F2(a, 1)))


def sqrt_f2(a):
    if a.is_zero():
        return F2(0)
    if not is_square_f2(a):
        return None
    return sqrt_generic(a, Q2, F2(1), lambda x, y: x * y, lambda b, e: b**e, F2_NONRES)


# --------------------------------------------------------------- Fp12 (flat)
# Fp12 = Fp2[w]/(w⁶ - u): coefficient list of six Fp2 elements. The tower
# Fp6 = Fp2[v]/(v³ - u), Fp12 = Fp6[w]/(w² - v) has v = w², so tower
# coefficient (Ci.Bj) is the flat coefficient of w^(i + 2j).
XI = F2(0, 1)


class F12:
    __slots__ = ("c",)

    def __init__(self, c):
        self.c = [f2(x) for x in c] + [F2(0)] * (6 - len(c))

    def __mul__(s, o):
        if not isinstance(o, F12):
            return F12([x * o for x in s.c])
        t = [F2(0)] * 11
        for i, a in enumerate(s.c):
            if a.is_zero():
                continue
            for j, b in enumerate(o.c):
                t[i + j] = t[i + j] + a * b
        for k in range(10, 5, -1):
            t[k - 6] = t[k - 6] + t[k] * XI
        return F12(t[:6])

    def __add__(s, o):
        return F12([a + b for a, b in zip(s.c, o.c)])

    def __sub__(s, o):
        return F12([a - b for a, b in zip(s.c, o.c)])

    def __eq__(s, o):
        return all(a == b for a, b in zip(s.c, o.c))

    def __pow__(s, e):
        r = F12([1])
        b = s
        while e:
            if e & 1:
                r = r * b
            b = b * b
            e >>= 1
        return r

    def frob(s):
        # (Σ c_k w^k)^p = Σ conj(c_k) w^(kp), w^(kp) = w^k · u^(k(p-1)/6)
        return F12([s.c[k].conj() * XI ** (k * (P - 1) // 6) for k in range(6)])

    def inv(s):
        return s ** (P**12 - 2)

    def tower(s):
        """[C0.B0, C0.B1, C0.B2, C1.B0, C1.B1, C1.B2] as Fp2 elements."""
        return [s.c[0], s.c[2], s.c[4], s.c[1], s.c[3], s.c[5]]


W = F12([0, 1])


# --------------------------------------------------------------- curves
B1 = 1
B2 = F2(1) / XI  # D-type twist: y² = x³ + 1/u


def ec_add(Pt, Qt, a=0, one=1):
    """Affine addition on y² = x³ + a·x + b over any field object set
    (works for ints mod P via wrappers and for F2); None is the identity."""
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt
    x1, y1 = Pt
    x2, y2 = Qt
    if x1 == x2:
        if y1 == -y2 or (y1 + y2) == 0 * one:
            return None
        lam = (3 * x1 * x1 + a) / (2 * y1)
    else:
        lam = (y2 - y1) / (x2 - x1)
    x3 = lam * lam - x1 - x2
    return (x3, lam * (x1 - x3) - y1)


class Fp:
    """Thin Fp wrapper so the generic curve code works over GF(p)."""

    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v % P

    def __add__(s, o):
        return Fp(s.v + fp(o).v)

    __radd__ = __add__

    def __sub__(s, o):
        return Fp(s.v - fp(o).v)

    def __rsub__(s, o):
        return Fp(fp(o).v - s.v)

    def __neg__(s):
        return Fp(-s.v)

    def __mul__(s, o):
        return Fp(s.v * fp(o).v)

    __rmul__ = __mul__

    def __truediv__(s, o):
        return Fp(s.v * inv(fp(o).v))

    def __eq__(s, o):
        return s.v == fp(o).v

    def __hash__(s):
        return hash(s.v)

    def __pow__(s, e):
        return Fp(pow(s.v, e, P))

    def __repr__(s):
        return hex(s.v)


def fp(a):
    return a if isinstance(a, Fp) else Fp(a)


def ec_mul(k, Pt, a=0):
    acc = None
    if k < 0:
        k = -k
        Pt = ec_neg(Pt)
    while k:
        if k & 1:
            acc = ec_add(acc, Pt, a)
        Pt = ec_add(Pt, Pt, a)
        k >>= 1
    return acc


def ec_neg(Pt):
    return None if Pt is None else (Pt[0], -Pt[1])


def on_curve(Pt, a, b):
    if Pt is None:
        return True
    x, y = Pt
    return y * y == x * x * x + a * x + b


# --------------------------------------------------------------- generators
# The standard generators (Zexe; also EIP-2539 / gnark-crypto Generators()).
G1 = (
    Fp(0x008848DEFE740A67C8FC6225BF87FF5485951E2CAA9D41BB188282C8BD37CB5CD5481512FFCD394EEAB9B16EB21BE9EF),
    Fp(0x01914A69C5102EFF1F674F5D30AFEEC4BD7FB348CA3E52D96D182AD44FB82305C2FE3D3634A9591AFD82DE55559C8EA6),
)
G2 = (
    F2(
        0x018480BE71C785FEC89630A2A3841D01C565F071203E50317EA501F557DB6B9B71889F52BB53540274E3E48F7C005196,
        0x00EA6040E700403170DC5A51B1B140D5532777EE6651CECBE7223ECE0799C9DE5CF89984BFF76FE6B26BFEFA6EA16AFE,
    ),
    F2(
        0x00690D665D446F7BD960736BCBB2EFB4DE03ED7274B49A58E458C282F832D204F2CF88886D8C7C2EF094094409FD4DDF,
        0x00F8169FD28355189E549DA3151A70AA61EF11AC3D591BF12463B01ACEE304C24279B83F5E52270BD9A1CDD185EB8F93,
    ),
)


# --------------------------------------------------------------- pairing
def untwist(Q):
    x, y = Q
    return (F12([0, 0, x]), F12([0, 0, 0, y]))  # (x·w², y·w³)


def miller_loop(Pt, Q):
    """f_{x,Q}(P) (x > 0), affine, lines evaluated on E(Fp12)."""
    px, py = F12([Pt[0].v]), F12([Pt[1].v])
    Qx, Qy = untwist(Q)

    def line(T, S):
        (tx, ty), (sx, sy) = T, S
        if tx == sx and ty == sy:
            lam = (tx * tx * F12([3])) * (ty * F12([2])).inv()
        else:
            lam = (sy - ty) * (sx - tx).inv()
        return py - ty - lam * (px - tx)

    def add12(T, S):
        (tx, ty), (sx, sy) = T, S
        if tx == sx and ty == sy:
            lam = (tx * tx * F12([3])) * (ty * F12([2])).inv()
        else:
            lam = (sy - ty) * (sx - tx).inv()
        x3 = lam * lam - tx - sx
        return (x3, lam * (tx - x3) - ty)

    T = (Qx, Qy)
    f = F12([1])
    for bit in bin(X)[3:]:
        f = f * f * line(T, T)
        T = add12(T, T)
        if bit == "1":
            f = f * line(T, (Qx, Qy))
            T = add12(T, (Qx, Qy))
    return f


def final_exp(f):
    return f ** ((P**12 - 1) // R)


def pairing(Pt, Q):
    return final_exp(miller_loop(Pt, Q))


def rand_fp():
    return Fp(random.randrange(P))
