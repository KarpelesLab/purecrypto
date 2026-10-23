// Generates tools/pairing-interop/bn254/vectors/gnark.json: BN254 interop
// vectors produced by driving gnark-crypto's public API as a black-box
// oracle. Deterministic: every input derives from SHA-256 of a counter.
//
//	cd tools/pairing-interop/bn254/gnark && go run ./gen > ../vectors/gnark.json
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	bn "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var ctr uint64

// next returns 32 deterministic pseudo-random bytes.
func next() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], ctr)
	ctr++
	h := sha256.Sum256(append([]byte("purecrypto bn254 vectors "), b[:]...))
	return h[:]
}

func h(b []byte) string { return hex.EncodeToString(b) }

func scalar() *big.Int {
	k := new(big.Int).SetBytes(next())
	return k.Mod(k, fr.Modulus())
}

func be32(k *big.Int) string {
	var out [32]byte
	k.FillBytes(out[:])
	return h(out[:])
}

var lines []string

func emit(format string, a ...any) {
	lines = append(lines, fmt.Sprintf(format, a...))
}

func main() {
	_, _, g1, g2 := bn.Generators()
	r := fr.Modulus()
	edge := []*big.Int{
		big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(15), big.NewInt(16),
		new(big.Int).Sub(r, big.NewInt(1)), new(big.Int).Sub(r, big.NewInt(2)),
		new(big.Int).Rsh(r, 1), new(big.Int).Lsh(big.NewInt(1), 253),
	}
	scalars := append([]*big.Int{}, edge...)
	for i := 0; i < 16; i++ {
		scalars = append(scalars, scalar())
	}

	// Scalar multiples of the generators and their encodings.
	for _, k := range scalars {
		var p bn.G1Affine
		p.ScalarMultiplication(&g1, k)
		c, u := p.Bytes(), p.RawBytes()
		emit(`{"kind": "g1", "k": "%s", "compressed": "%s", "uncompressed": "%s"}`, be32(k), h(c[:]), h(u[:]))
	}
	for _, k := range scalars {
		var q bn.G2Affine
		q.ScalarMultiplication(&g2, k)
		c, u := q.Bytes(), q.RawBytes()
		emit(`{"kind": "g2", "k": "%s", "compressed": "%s", "uncompressed": "%s"}`, be32(k), h(c[:]), h(u[:]))
	}

	// Point addition on arbitrary multiples.
	for i := 0; i < 4; i++ {
		var a, b, s bn.G1Affine
		a.ScalarMultiplication(&g1, scalar())
		b.ScalarMultiplication(&g1, scalar())
		s.Add(&a, &b)
		ab, bb, sb := a.RawBytes(), b.RawBytes(), s.RawBytes()
		emit(`{"kind": "g1add", "a": "%s", "b": "%s", "sum": "%s"}`, h(ab[:]), h(bb[:]), h(sb[:]))
		var c, d, t bn.G2Affine
		c.ScalarMultiplication(&g2, scalar())
		d.ScalarMultiplication(&g2, scalar())
		t.Add(&c, &d)
		cb, db, tb := c.RawBytes(), d.RawBytes(), t.RawBytes()
		emit(`{"kind": "g2add", "a": "%s", "b": "%s", "sum": "%s"}`, h(cb[:]), h(db[:]), h(tb[:]))
	}

	// Pairings e(a·G1, b·G2) as gnark's 384-byte GT encoding.
	pk := [][2]*big.Int{{big.NewInt(1), big.NewInt(1)}, {big.NewInt(0), big.NewInt(1)}, {big.NewInt(1), big.NewInt(0)}}
	for i := 0; i < 6; i++ {
		pk = append(pk, [2]*big.Int{scalar(), scalar()})
	}
	for _, ab := range pk {
		var p bn.G1Affine
		var q bn.G2Affine
		p.ScalarMultiplication(&g1, ab[0])
		q.ScalarMultiplication(&g2, ab[1])
		e, err := bn.Pair([]bn.G1Affine{p}, []bn.G2Affine{q})
		if err != nil {
			panic(err)
		}
		eb := e.Bytes()
		emit(`{"kind": "pairing", "a": "%s", "b": "%s", "gt": "%s"}`, be32(ab[0]), be32(ab[1]), h(eb[:]))
	}

	// EIP-197 style pairing-check inputs, valid (product 1) and not.
	for n := 1; n <= 12; n++ {
		ps := make([]bn.G1Affine, n)
		qs := make([]bn.G2Affine, n)
		for i := range ps {
			ps[i].ScalarMultiplication(&g1, scalar())
			qs[i].ScalarMultiplication(&g2, scalar())
		}
		// Make the product 1 for even n by balancing the last pair:
		// e(P_last, Q_last) = ∏_{i<last} e(P_i, Q_i)^(-1), with Q_last = G2
		// and P_last = -Σ a_i b_i · G1 computed from fresh scalars.
		if n%2 == 0 {
			sum := big.NewInt(0)
			for i := 0; i < n-1; i++ {
				a, b := scalar(), scalar()
				ps[i].ScalarMultiplication(&g1, a)
				qs[i].ScalarMultiplication(&g2, b)
				sum.Add(sum, new(big.Int).Mul(a, b))
			}
			sum.Neg(sum)
			sum.Mod(sum, r)
			ps[n-1].ScalarMultiplication(&g1, sum)
			qs[n-1].Set(&g2)
		}
		ok, err := bn.PairingCheck(ps, qs)
		if err != nil {
			panic(err)
		}
		var sb strings.Builder
		for i := range ps {
			pb, qb := ps[i].RawBytes(), qs[i].RawBytes()
			sb.WriteString(h(pb[:]))
			sb.WriteString(h(qb[:]))
		}
		emit(`{"kind": "pairing_check", "input": "%s", "result": %t}`, sb.String(), ok)
	}

	// Hash-to-curve, RFC 9380 J-style message set.
	msgs := []string{"", "abc", "abcdef0123456789", "q128_" + strings.Repeat("q", 128), "a512_" + strings.Repeat("a", 512)}
	type suite struct {
		name string
		dst  string
		f    func(m, d []byte) ([]byte, error)
	}
	suites := []suite{
		{"BN254G1_XMD:SHA-256_SVDW_RO_", "QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_", func(m, d []byte) ([]byte, error) {
			p, err := bn.HashToG1(m, d)
			b := p.RawBytes()
			return b[:], err
		}},
		{"BN254G1_XMD:SHA-256_SVDW_NU_", "QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_NU_", func(m, d []byte) ([]byte, error) {
			p, err := bn.EncodeToG1(m, d)
			b := p.RawBytes()
			return b[:], err
		}},
		{"BN254G2_XMD:SHA-256_SVDW_RO_", "QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_RO_", func(m, d []byte) ([]byte, error) {
			p, err := bn.HashToG2(m, d)
			b := p.RawBytes()
			return b[:], err
		}},
		{"BN254G2_XMD:SHA-256_SVDW_NU_", "QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_NU_", func(m, d []byte) ([]byte, error) {
			p, err := bn.EncodeToG2(m, d)
			b := p.RawBytes()
			return b[:], err
		}},
	}
	for _, s := range suites {
		for _, m := range msgs {
			out, err := s.f([]byte(m), []byte(s.dst))
			if err != nil {
				panic(err)
			}
			emit(`{"kind": "h2c", "suite": "%s", "dst": "%s", "msg": "%s", "point": "%s"}`, s.name, s.dst, h([]byte(m)), h(out))
		}
	}

	// The raw maps on field elements (gnark's MapToG1 / MapToG2).
	for i := 0; i < 6; i++ {
		var u fp.Element
		u.SetBytes(next())
		if i == 0 {
			u.SetZero()
		}
		p := bn.MapToG1(u)
		ub := u.Bytes()
		pb := p.RawBytes()
		emit(`{"kind": "map_g1", "u": "%s", "point": "%s"}`, h(ub[:]), h(pb[:]))
		var u2 bn.E2
		u2.A0.SetBytes(next())
		u2.A1.SetBytes(next())
		if i == 0 {
			u2.SetZero()
		}
		q := bn.MapToG2(u2)
		a0, a1 := u2.A0.Bytes(), u2.A1.Bytes()
		qb := q.RawBytes()
		emit(`{"kind": "map_g2", "u0": "%s", "u1": "%s", "point": "%s"}`, h(a0[:]), h(a1[:]), h(qb[:]))
	}

	// Twist points outside G2 (MapToCurve2 skips cofactor clearing): gnark's
	// decoder must reject them, and so must ours.
	for i := 0; i < 3; i++ {
		var u2 bn.E2
		u2.A0.SetBytes(next())
		u2.A1.SetBytes(next())
		q := bn.MapToCurve2(&u2)
		if q.IsInSubGroup() {
			panic("map output unexpectedly in G2")
		}
		raw := q.RawBytes()
		var chk bn.G2Affine
		if _, err := chk.SetBytes(raw[:]); err == nil {
			panic("gnark accepted a non-subgroup point")
		}
		c := q.Bytes()
		if _, err := chk.SetBytes(c[:]); err == nil {
			panic("gnark accepted a non-subgroup compressed point")
		}
		emit(`{"kind": "g2_not_in_subgroup", "compressed": "%s", "uncompressed": "%s"}`, h(c[:]), h(raw[:]))
	}

	fmt.Println("[")
	fmt.Println(strings.Join(lines, ",\n"))
	fmt.Println("]")
}
