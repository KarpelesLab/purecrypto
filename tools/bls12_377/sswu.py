"""Reference RFC 9380 Simplified SWU (variable time) and find_z_sswu."""
from ref377 import P, F2, Fp, is_square_fp, is_square_f2, sqrt_fp, sqrt_f2


def sgn0_fp(x):
    return x.v & 1


def sgn0_f2(x):
    return (x.c0 & 1) | ((x.c0 == 0) & (x.c1 & 1))


def has_root(coeffs, field):
    """Whether the cubic x³ + c2x² + c1x + c0 has a root in the field (by gcd
    with x^q - x, computed with simple polynomial arithmetic)."""
    import polyf2 as pf
    if field == "fp":
        c = lambda v: (v.v % P, 0)
        q = P
    else:
        c = lambda v: (v.c0, v.c1)
        q = P * P
    poly = pf.trim(([c(x)[0] for x in coeffs], [c(x)[1] for x in coeffs]))
    if field == "fp":
        # Over Fp: x^p - x; all coefficients have c1 = 0, and gcd over Fp2
        # with x^p - x detects Fp-rational roots.
        M = pf.Modulus(poly)
        xp = M.powmod(pf.X, P)
    else:
        M = pf.Modulus(poly)
        xp = M.powmod(pf.X, q)
    g = pf.gcd(poly, pf.sub(xp, pf.X))
    return pf.deg(g) > 0


def find_z_sswu_fp(A, B):
    ctr = 1
    while True:
        for z in (Fp(ctr), Fp(-ctr)):
            if is_square_fp(z.v) or z == Fp(-1):
                continue
            if has_root([B - z, A, Fp(0), Fp(1)], "fp"):
                continue
            x = B / (z * A)
            if is_square_fp((x * x * x + A * x + B).v):
                return z
        ctr += 1


def find_z_sswu_f2(A, B):
    k = 0
    while True:
        ctr = F2(k, 1)
        for z in (ctr, -ctr):
            if is_square_f2(z) or z == F2(-1):
                continue
            if has_root([B - z, A, F2(0), F2(1)], "f2"):
                continue
            x = B / (z * A)
            if is_square_f2(x * x * x + A * x + B):
                return z
        k += 1


def sswu(u, A, B, Z, sgn0, is_sq, sqrt):
    """RFC 9380 §6.6.2 (straight from the definition)."""
    tv1 = Z * Z * u * u * u * u + Z * u * u
    if tv1 == tv1 * 0:
        x1 = B / (Z * A)
    else:
        x1 = (B * -1) / A * (inv_(tv1) + 1)
    gx1 = x1 * x1 * x1 + A * x1 + B
    x2 = Z * u * u * x1
    gx2 = x2 * x2 * x2 + A * x2 + B
    if is_sq(gx1):
        x, y = x1, sqrt(gx1)
    else:
        x, y = x2, sqrt(gx2)
    if sgn0(u) != sgn0(y):
        y = -y
    return x, y


def inv_(t):
    return t.__class__(1) / t
