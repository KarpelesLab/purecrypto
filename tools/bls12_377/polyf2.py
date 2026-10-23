"""Polynomials over Fp2 = Fp[u]/(u² + 5) for BLS12-377, with Kronecker-
substitution multiplication (one big-integer product per Fp[x] product).

A polynomial is a pair of coefficient lists `(c0s, c1s)` (low degree first)
of equal length, trimmed so the leading Fp2 coefficient is nonzero. Used
only to derive the G2 isogeny for hash-to-curve (see derive_iso2.py).
"""
import random

from ref377 import P

W = 800  # slot width: covers n·(p²)·10 for n < 2^20
MASK = (1 << W) - 1


def pack(lst):
    v = 0
    for c in reversed(lst):
        v = (v << W) | c
    return v


def unpack(v, n):
    out = []
    for _ in range(n):
        out.append((v & MASK) % P)
        v >>= W
    return out


def trim(a):
    c0, c1 = a
    n = len(c0)
    while n and c0[n - 1] == 0 and c1[n - 1] == 0:
        n -= 1
    return (c0[:n], c1[:n])


def deg(a):
    return len(a[0]) - 1


def const(c0, c1=0):
    return trim(([c0 % P], [c1 % P]))


X = ([0, 1], [0, 0])
ONE = ([1], [0])


def add(a, b):
    n = max(len(a[0]), len(b[0]))
    pa = lambda l: l + [0] * (n - len(l))
    return trim(([(x + y) % P for x, y in zip(pa(a[0]), pa(b[0]))], [(x + y) % P for x, y in zip(pa(a[1]), pa(b[1]))]))


def neg(a):
    return ([(-x) % P for x in a[0]], [(-x) % P for x in a[1]])


def sub(a, b):
    return add(a, neg(b))


def mul(a, b):
    if not a[0] or not b[0]:
        return ([], [])
    n = len(a[0]) + len(b[0]) - 1
    A0, A1, B0, B1 = pack(a[0]), pack(a[1]), pack(b[0]), pack(b[1])
    t0 = unpack(A0 * B0, n)
    t1 = unpack(A1 * B1, n)
    t2 = unpack((A0 + A1) * (B0 + B1), n)
    c0 = [(x - 5 * y) % P for x, y in zip(t0, t1)]
    c1 = [(z - x - y) % P for x, y, z in zip(t0, t1, t2)]
    return trim((c0, c1))


def scale(a, s):
    s0, s1 = s
    return trim(([(x * s0 - 5 * y * s1) % P for x, y in zip(*a)], [(x * s1 + y * s0) % P for x, y in zip(*a)]))


def f2inv(s):
    s0, s1 = s
    n = pow((s0 * s0 + 5 * s1 * s1) % P, -1, P)
    return (s0 * n % P, -s1 * n % P)


def lead(a):
    return (a[0][-1], a[1][-1])


def monic(a):
    return scale(a, f2inv(lead(a)))


def truncate(a, k):
    return trim((a[0][:k], a[1][:k]))


def rev(a, d):
    c0 = a[0] + [0] * (d + 1 - len(a[0]))
    c1 = a[1] + [0] * (d + 1 - len(a[1]))
    return trim((c0[: d + 1][::-1], c1[: d + 1][::-1]))


def series_inv(a, k):
    """1/a mod x^k (a[0] invertible), Newton iteration."""
    g = (lambda s: ([s[0]], [s[1]]))(f2inv((a[0][0], a[1][0])))
    prec = 1
    while prec < k:
        prec = min(2 * prec, k)
        # g = g (2 - a g)
        ag = truncate(mul(truncate(a, prec), g), prec)
        two_minus = sub(const(2), ag)
        g = truncate(mul(g, two_minus), prec)
    return g


class Modulus:
    def __init__(self, m):
        self.m = monic(m)
        self.n = deg(self.m)
        self.rinv = series_inv(rev(self.m, self.n), self.n)

    def reduce(self, a):
        da = deg(a)
        n = self.n
        if da < n:
            return a
        if da > 2 * n - 2:
            # generic slow path: split
            q, r = divmod_slow(a, self.m)
            return r
        k = da - n + 1
        ra = truncate(rev(a, da), k)
        rq = truncate(mul(ra, truncate(self.rinv, k)), k)
        q = rev(rq, k - 1)
        r = sub(a, mul(q, self.m))
        return truncate(r, n)

    def mulmod(self, a, b):
        return self.reduce(mul(a, b))

    def powmod(self, a, e):
        r = ONE
        a = self.reduce(a)
        for bit in bin(e)[2:]:
            r = self.mulmod(r, r)
            if bit == "1":
                r = self.mulmod(r, a)
        return r


def divmod_slow(a, b):
    a = (a[0][:], a[1][:])
    b = monic(b) if lead(b) != (1, 0) else b
    lb = f2inv(lead(b))
    db = deg(b)
    qn = max(0, deg(a) - db + 1)
    q0, q1 = [0] * qn, [0] * qn
    c0, c1 = a
    while len(c0) - 1 >= db and len(c0) > 0:
        co = (c0[-1], c1[-1])
        co = ((co[0] * lb[0] - 5 * co[1] * lb[1]) % P, (co[0] * lb[1] + co[1] * lb[0]) % P)
        s = len(c0) - 1 - db
        q0[s], q1[s] = co
        for i in range(db + 1):
            x0, x1 = b[0][i], b[1][i]
            c0[s + i] = (c0[s + i] - (co[0] * x0 - 5 * co[1] * x1)) % P
            c1[s + i] = (c1[s + i] - (co[0] * x1 + co[1] * x0)) % P
        while c0 and c0[-1] == 0 and c1[-1] == 0:
            c0.pop()
            c1.pop()
    return trim((q0, q1)), trim((c0, c1))


def divexact(a, b):
    q, r = divmod_slow(a, b)
    assert not r[0], "not exact"
    # undo monic normalisation of b
    if lead(b) != (1, 0):
        q = scale(q, f2inv(lead(b)))
    return q


def gcd(a, b):
    a, b = trim(a), trim(b)
    while b[0]:
        a, b = b, divmod_slow(a, b)[1]
    return monic(a) if a[0] else a


def derivative(a):
    return trim(([(i * x) % P for i, x in enumerate(a[0])][1:], [(i * x) % P for i, x in enumerate(a[1])][1:]))


def evaluate(a, x):
    """Horner at an Fp2 point x = (x0, x1)."""
    r0, r1 = 0, 0
    for c0, c1 in zip(reversed(a[0]), reversed(a[1])):
        r0, r1 = (r0 * x[0] - 5 * r1 * x[1] + c0) % P, (r0 * x[1] + r1 * x[0] + c1) % P
    return (r0, r1)


def random_poly(n):
    return trim(([random.randrange(P) for _ in range(n)], [random.randrange(P) for _ in range(n)]))


def edf(g, k, q):
    """Equal-degree factorisation of g (product of distinct irreducibles of
    degree k over GF(q))."""
    n = deg(g) // k
    if n <= 1:
        return [g]
    M = Modulus(g)
    while True:
        a = random_poly(deg(g))
        h = M.powmod(a, (q**k - 1) // 2)
        d = gcd(g, sub(h, ONE))
        if 0 < deg(d) < deg(g):
            return edf(d, k, q) + edf(divexact(g, d), k, q)
