// Probe: prints gnark-crypto's BN254 G2 map outputs and compressed
// encodings of a few points, used to recover the cofactor clearing and the
// compressed sort order by inspection (black-box; public API only).
package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	bn "github.com/consensys/gnark-crypto/ecc/bn254"
)

func h(b []byte) string { return hex.EncodeToString(b) }

func main() {
	for i := uint64(1); i <= 2; i++ {
		var u bn.E2
		u.A0.SetUint64(i)
		u.A1.SetUint64(i + 7)
		p := bn.MapToCurve2(&u)
		fmt.Println("mc2", i, p.X.A0.String(), p.X.A1.String(), p.Y.A0.String(), p.Y.A1.String())
		m := bn.MapToG2(u)
		fmt.Println("mg2", i, m.X.A0.String(), m.X.A1.String(), m.Y.A0.String(), m.Y.A1.String())
	}
	_, _, _, g2 := bn.Generators()
	for i := int64(1); i <= 6; i++ {
		var q bn.G2Affine
		q.ScalarMultiplication(&g2, big.NewInt(i*1000003))
		c := q.Bytes()
		fmt.Println("pt", q.X.A0.String(), q.X.A1.String(), q.Y.A0.String(), q.Y.A1.String(), h(c[:1]))
	}
	q, _ := bn.HashToG2([]byte("abc"), []byte("QUUX-V01-CS02-with-BN254G2_XMD:SHA-256_SVDW_RO_"))
	fmt.Println("h2 abc", q.X.A0.String(), q.X.A1.String(), q.Y.A0.String(), q.Y.A1.String())
}
