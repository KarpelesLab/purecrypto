#!/usr/bin/env python3
"""Derives the G2 SSWU isogeny of BLS12-377 from first principles.

Input: the isogenous curve E'2: y² = x³ + A'·x + B' over Fp2 (recovered from
gnark-crypto's `MapToCurve2` outputs; see the README). Output: a JSON file
with the kernel polynomial and the rational map onto E2: y² = x³ + 1/u.

Method:
  * the Frobenius conductor of E'2 has 23 as its only small prime factor, so
    the isogeny ascending to the j = 0 curve has degree 23;
  * Frobenius has the double eigenvalue 12 (mod 23), of order 11 modulo ±1,
    so every 23-kernel polynomial is a degree-11 factor of the 23-division
    polynomial ψ₂₃ (degree 264), all of which split off by an equal-degree
    factorisation over GF(q¹¹);
  * Kohel's formulas give each candidate's codomain; exactly one has j = 0;
  * its normalised rational map (Vélu) composed with one of the six
    isomorphisms onto y² = x³ + 1/u.

Usage: python3 derive_iso2.py A0 A1 B0 B1 > iso2.json   (hex coordinates)
"""
import json
import sys
import time

import polyf2 as pf
from ref377 import P, F2, B2

q = P * P


def f2t(s):
    return (s.c0, s.c1)


def division_polynomial(n, a, b):
    """f_n with ψ_n = f_n (n odd) or y·f_n (n even), y² = x³ + a x + b."""
    F = pf.trim(([b[0], a[0], 0, 1], [b[1], a[1], 0, 0]))
    F2p = pf.mul(F, F)
    c = lambda v: pf.const(v)
    A = pf.const(*a)
    Bc = pf.const(*b)
    xp = lambda k: pf.trim(([0] * k + [1], [0] * (k + 1)))
    cache = {0: ([], []), 1: pf.ONE, 2: c(2)}
    # ψ3 = 3x⁴ + 6a x² + 12 b x - a²
    cache[3] = pf.add(pf.add(pf.add(pf.scale(xp(4), (3, 0)), pf.scale(pf.mul(A, xp(2)), (6, 0))), pf.scale(pf.mul(Bc, xp(1)), (12, 0))), pf.neg(pf.mul(A, A)))
    # ψ4/y = 4(x⁶ + 5a x⁴ + 20 b x³ - 5a² x² - 4ab x - 8b² - a³)
    t = xp(6)
    t = pf.add(t, pf.scale(pf.mul(A, xp(4)), (5, 0)))
    t = pf.add(t, pf.scale(pf.mul(Bc, xp(3)), (20, 0)))
    t = pf.sub(t, pf.scale(pf.mul(pf.mul(A, A), xp(2)), (5, 0)))
    t = pf.sub(t, pf.scale(pf.mul(pf.mul(A, Bc), xp(1)), (4, 0)))
    t = pf.sub(t, pf.scale(pf.mul(Bc, Bc), (8, 0)))
    t = pf.sub(t, pf.mul(A, pf.mul(A, A)))
    cache[4] = pf.scale(t, (4, 0))
    half = pf.f2inv((2, 0))

    def get(k):
        if k in cache:
            return cache[k]
        m = k // 2
        if k % 2:
            u = pf.mul(get(m + 2), pf.mul(get(m), pf.mul(get(m), get(m))))
            v = pf.mul(get(m - 1), pf.mul(get(m + 1), pf.mul(get(m + 1), get(m + 1))))
            if m % 2 == 0:
                u = pf.mul(u, F2p)
            else:
                v = pf.mul(v, F2p)
            cache[k] = pf.sub(u, v)
        else:
            t1 = pf.mul(get(m + 2), pf.mul(get(m - 1), get(m - 1)))
            t2 = pf.mul(get(m - 2), pf.mul(get(m + 1), get(m + 1)))
            cache[k] = pf.scale(pf.mul(get(m), pf.sub(t1, t2)), half)
        return cache[k]

    return get(n)


def kohel(D, a, b):
    """Codomain (A'', B'') and normalised x-map numerator N (X = N/D²)."""
    d = pf.deg(D)
    co = lambda i: (D[0][i], D[1][i]) if i >= 0 else (0, 0)
    F = F2
    s1 = -F(*co(d - 1))
    s2 = F(*co(d - 2))
    s3 = -F(*co(d - 3))
    p1 = s1
    p2 = s1 * s1 - 2 * s2
    p3 = s1 * s1 * s1 - 3 * s1 * s2 + 3 * s3
    aF, bF = F(*a), F(*b)
    t = 6 * p2 + 2 * d * aF
    w = 10 * p3 + 6 * aF * p1 + 4 * d * bF
    A2 = aF - 5 * t
    B2_ = bF - 7 * w
    # N = x D² + 6(x² D' D − (d x + p1) D²) + 2a D' D
    #     + 4(F (D'² − D D'') − F' D' D + (2 d x + p1) D²)
    Dp = pf.derivative(D)
    Dpp = pf.derivative(Dp)
    D2 = pf.mul(D, D)
    DDp = pf.mul(D, Dp)
    Fx = pf.trim(([b[0], a[0], 0, 1], [b[1], a[1], 0, 0]))
    Fp_ = pf.derivative(Fx)
    x1 = pf.X
    x2 = pf.mul(x1, x1)
    lin = lambda c1, c0: pf.add(pf.scale(x1, f2t(F(c1))), pf.const(*f2t(c0)))
    N = pf.mul(x1, D2)
    N = pf.add(N, pf.scale(pf.sub(pf.mul(x2, DDp), pf.mul(lin(d, p1), D2)), (6, 0)))
    N = pf.add(N, pf.scale(DDp, f2t(2 * aF)))
    inner = pf.sub(pf.mul(Fx, pf.sub(pf.mul(Dp, Dp), pf.mul(D, Dpp))), pf.mul(Fp_, DDp))
    inner = pf.add(inner, pf.mul(lin(2 * d, p1), D2))
    N = pf.add(N, pf.scale(inner, (4, 0)))
    return A2, B2_, N


def main():
    a = (int(sys.argv[1], 16), int(sys.argv[2], 16))
    b = (int(sys.argv[3], 16), int(sys.argv[4], 16))
    t0 = time.time()
    psi = pf.monic(division_polynomial(23, a, b))
    assert pf.deg(psi) == 264
    print(f"psi23 built ({time.time()-t0:.0f}s)", file=sys.stderr)
    M = pf.Modulus(psi)
    xq = M.powmod(pf.X, q)
    # x^(q^11) by repeated q-powering of x^q (composition via powmod is
    # simpler than modular composition and fast enough here).
    h = xq
    for _ in range(10):
        h = M.powmod(h, q)
    print(f"x^(q^11) mod psi23 computed ({time.time()-t0:.0f}s)", file=sys.stderr)
    g = pf.gcd(psi, pf.sub(h, pf.X))
    print("degree of the GF(q^11)-split part:", pf.deg(g), file=sys.stderr)
    found = []

    def search(g):
        # Split until degree-11 pieces, testing each with Kohel.
        if pf.deg(g) == 11:
            A2, B2_, N = kohel(g, a, b)
            if A2.is_zero():
                found.append((g, B2_, N))
            return
        Mg = pf.Modulus(g)
        while True:
            r = pf.random_poly(pf.deg(g))
            hh = Mg.powmod(r, (q**11 - 1) // 2)
            dd = pf.gcd(g, pf.sub(hh, pf.ONE))
            if 0 < pf.deg(dd) < pf.deg(g):
                break
        print(f"  split {pf.deg(g)} -> {pf.deg(dd)} + {pf.deg(g)-pf.deg(dd)} ({time.time()-t0:.0f}s)", file=sys.stderr)
        search(dd)
        search(pf.divexact(g, dd))

    search(g)
    assert len(found) == 1, f"expected one ascending kernel, got {len(found)}"
    D, B2_, N = found[0]
    out = {
        "l": 23,
        "D": [list(map(hex, D[0])), list(map(hex, D[1]))],
        "N": [list(map(hex, N[0])), list(map(hex, N[1]))],
        "B_codomain": [hex(B2_.c0), hex(B2_.c1)],
    }
    json.dump(out, sys.stdout, indent=1)
    print(f"done ({time.time()-t0:.0f}s)", file=sys.stderr)


if __name__ == "__main__":
    main()
