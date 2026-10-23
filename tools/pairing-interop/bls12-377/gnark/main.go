// Black-box vector generator for purecrypto's BLS12-377 module.
//
// Drives only the exported API of github.com/consensys/gnark-crypto
// (ecc/bls12-377) and prints a JSON document on stdout. See ../README.md.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

func fpHex(e *fp.Element) string {
	b := e.Bytes()
	return hex.EncodeToString(b[:])
}

func e2Hex(e *bls.E2) [2]string { return [2]string{fpHex(&e.A0), fpHex(&e.A1)} }

type g1Out struct {
	X, Y  string
	Comp  string
	Raw   string
}

type g2Out struct {
	X, Y [2]string
	Comp string
	Raw  string
}

func g1o(p *bls.G1Affine) g1Out {
	c := p.Bytes()
	r := p.RawBytes()
	return g1Out{fpHex(&p.X), fpHex(&p.Y), hex.EncodeToString(c[:]), hex.EncodeToString(r[:])}
}

func g2o(p *bls.G2Affine) g2Out {
	c := p.Bytes()
	r := p.RawBytes()
	return g2Out{e2Hex(&p.X), e2Hex(&p.Y), hex.EncodeToString(c[:]), hex.EncodeToString(r[:])}
}

// Deterministic scalars: SHA-256 chain reduced mod r, plus edge values.
func scalars() []*big.Int {
	out := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(0x1234567)}
	rm1 := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	out = append(out, rm1)
	seed := sha256.Sum256([]byte("purecrypto bls12-377 scalars"))
	for i := 0; i < 8; i++ {
		k := new(big.Int).SetBytes(seed[:])
		k.Mod(k, fr.Modulus())
		out = append(out, k)
		seed = sha256.Sum256(seed[:])
	}
	return out
}

type pairOut struct {
	A, B  string
	GT    string
	Coeff [12]string
}

type hashOut struct {
	Msg, Dst string
	G1Hash   g1Out
	G1Encode g1Out
	G2Hash   g2Out
	G2Encode g2Out
}

type mapOut struct {
	U     string
	Iso   g1Out // MapToCurve1 output, on the isogenous curve (encodings meaningless)
	Group g1Out
}

type map2Out struct {
	U     [2]string
	Iso   [2][2]string
	Group g2Out
}

type doc struct {
	Tower     map[string]string
	G1Gen     g1Out
	G2Gen     g2Out
	G1Inf     g1Out
	G2Inf     g2Out
	Scalars   []string
	G1Mul     []g1Out
	G2Mul     []g2Out
	Pairings  []pairOut
	Hashes    []hashOut
	Map1      []mapOut
	Map2      []map2Out
}

func main() {
	var d doc
	d.Tower = map[string]string{}
	var u bls.E2
	u.A1.SetOne()
	var uu bls.E2
	uu.Square(&u)
	d.Tower["u^2"] = uu.String()
	var v bls.E6
	v.B1.SetOne()
	var v3 bls.E6
	v3.Mul(&v, &v).Mul(&v3, &v)
	d.Tower["v^3"] = v3.String()
	var w bls.E12
	w.C1.B0.SetOne()
	var w2 bls.E12
	w2.Square(&w)
	d.Tower["w^2"] = w2.String()

	_, _, g1, g2 := bls.Generators()
	d.G1Gen = g1o(&g1)
	d.G2Gen = g2o(&g2)
	var i1 bls.G1Affine
	i1.SetInfinity()
	d.G1Inf = g1o(&i1)
	var i2 bls.G2Affine
	i2.SetInfinity()
	d.G2Inf = g2o(&i2)

	ks := scalars()
	for _, k := range ks {
		d.Scalars = append(d.Scalars, hex.EncodeToString(k.FillBytes(make([]byte, 32))))
		var p bls.G1Affine
		p.ScalarMultiplication(&g1, k)
		d.G1Mul = append(d.G1Mul, g1o(&p))
		var q bls.G2Affine
		q.ScalarMultiplication(&g2, k)
		d.G2Mul = append(d.G2Mul, g2o(&q))
	}

	for i := 0; i+1 < len(ks); i += 2 {
		var p bls.G1Affine
		p.ScalarMultiplication(&g1, ks[i])
		var q bls.G2Affine
		q.ScalarMultiplication(&g2, ks[i+1])
		e, err := bls.Pair([]bls.G1Affine{p}, []bls.G2Affine{q})
		if err != nil {
			panic(err)
		}
		b := e.Bytes()
		po := pairOut{A: d.Scalars[i], B: d.Scalars[i+1], GT: hex.EncodeToString(b[:])}
		cs := []*fp.Element{&e.C0.B0.A0, &e.C0.B0.A1, &e.C0.B1.A0, &e.C0.B1.A1, &e.C0.B2.A0, &e.C0.B2.A1,
			&e.C1.B0.A0, &e.C1.B0.A1, &e.C1.B1.A0, &e.C1.B1.A1, &e.C1.B2.A0, &e.C1.B2.A1}
		for j, c := range cs {
			po.Coeff[j] = fpHex(c)
		}
		d.Pairings = append(d.Pairings, po)
	}

	msgs := []string{"", "abc", "abcdef0123456789",
		"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
		"a512_" + string(make([]byte, 0))}
	// a512_aaa… exactly as in RFC 9380's vectors.
	a := "a512_"
	for len(a) < 517 {
		a += "a"
	}
	msgs[4] = a
	dst1 := "QUUX-V01-CS02-with-BLS12377G1_XMD:SHA-256_SSWU_RO_"
	dst1nu := "QUUX-V01-CS02-with-BLS12377G1_XMD:SHA-256_SSWU_NU_"
	dst2 := "QUUX-V01-CS02-with-BLS12377G2_XMD:SHA-256_SSWU_RO_"
	dst2nu := "QUUX-V01-CS02-with-BLS12377G2_XMD:SHA-256_SSWU_NU_"
	for _, m := range msgs {
		h1, err := bls.HashToG1([]byte(m), []byte(dst1))
		if err != nil {
			panic(err)
		}
		e1, _ := bls.EncodeToG1([]byte(m), []byte(dst1nu))
		h2, _ := bls.HashToG2([]byte(m), []byte(dst2))
		e2, _ := bls.EncodeToG2([]byte(m), []byte(dst2nu))
		d.Hashes = append(d.Hashes, hashOut{m, dst1 + "|" + dst1nu + "|" + dst2 + "|" + dst2nu, g1o(&h1), g1o(&e1), g2o(&h2), g2o(&e2)})
	}

	for i := uint64(0); i < 6; i++ {
		var e fp.Element
		e.SetUint64(i*i*977 + 1)
		if i == 0 {
			e.SetZero()
		}
		iso := bls.MapToCurve1(&e)
		grp := bls.MapToG1(e)
		d.Map1 = append(d.Map1, mapOut{fpHex(&e), g1Out{X: fpHex(&iso.X), Y: fpHex(&iso.Y)}, g1o(&grp)})
		var e2 bls.E2
		e2.A0.SetUint64(i*31 + 5)
		e2.A1.SetUint64(i*i + 7)
		if i == 0 {
			e2.SetZero()
		}
		iso2 := bls.MapToCurve2(&e2)
		grp2 := bls.MapToG2(e2)
		d.Map2 = append(d.Map2, map2Out{e2Hex(&e2), [2][2]string{e2Hex(&iso2.X), e2Hex(&iso2.Y)}, g2o(&grp2)})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(d); err != nil {
		panic(err)
	}
}
