// Black-box BLS signature vectors for BN254 and BLS12-377 from gnark-crypto's
// public API: SkToPk = sk·G, CoreSign = sk·HashToG(msg, DST), with the
// draft-irtf-cfrg-bls-signature-05 ciphersuite IDs purecrypto documents.
// gnark-crypto has no BLS signature package; only its scalar multiplication,
// hash-to-curve and point encodings are used.
//
//	go run . < ../vectors/keygen.jsonl > ../vectors/gnark.jsonl
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bn "github.com/consensys/gnark-crypto/ecc/bn254"
)

type keyRec struct {
	Curve   string `json:"curve"`
	Ikm     string `json:"ikm"`
	KeyInfo string `json:"key_info"`
	Sk      string `json:"sk"`
}

type sigRec struct {
	Curve   string `json:"curve"`
	Variant string `json:"variant"`
	Ikm     string `json:"ikm"`
	KeyInfo string `json:"key_info"`
	Sk      string `json:"sk"`
	Pk      string `json:"pk"`
	Pop     string `json:"pop"`
	Msg     string `json:"msg"`
	Basic   string `json:"basic"`
	Aug     string `json:"aug"`
	PopSig  string `json:"pop_sig"`
}

var msgs = [][]byte{
	{},
	[]byte("abc"),
	[]byte("abcdef0123456789"),
	[]byte("purecrypto BLS signature vector"),
	make([]byte, 300),
}

func suites(curve, variant string) string {
	switch curve + "/" + variant {
	case "bn254/min_pk":
		return "BN254G2_XMD:SHA-256_SVDW_RO_"
	case "bn254/min_sig":
		return "BN254G1_XMD:SHA-256_SVDW_RO_"
	case "bls12-377/min_pk":
		return "BLS12377G2_XMD:SHA-256_SSWU_RO_"
	case "bls12-377/min_sig":
		return "BLS12377G1_XMD:SHA-256_SSWU_RO_"
	}
	panic(curve + variant)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// One curve/variant: returns pk bytes and a signing function.
type signer struct {
	pk   []byte
	sign func(msg, dst []byte) []byte
}

func mkSigner(curve, variant string, sk *big.Int) signer {
	switch curve + "/" + variant {
	case "bn254/min_pk":
		var pk bn.G1Affine
		pk.ScalarMultiplicationBase(sk)
		b := pk.Bytes()
		return signer{b[:], func(m, d []byte) []byte {
			h, err := bn.HashToG2(m, d)
			must(err)
			var s bn.G2Affine
			s.ScalarMultiplication(&h, sk)
			o := s.Bytes()
			return o[:]
		}}
	case "bn254/min_sig":
		var pk bn.G2Affine
		pk.ScalarMultiplicationBase(sk)
		b := pk.Bytes()
		return signer{b[:], func(m, d []byte) []byte {
			h, err := bn.HashToG1(m, d)
			must(err)
			var s bn.G1Affine
			s.ScalarMultiplication(&h, sk)
			o := s.Bytes()
			return o[:]
		}}
	case "bls12-377/min_pk":
		var pk bls.G1Affine
		pk.ScalarMultiplicationBase(sk)
		b := pk.Bytes()
		return signer{b[:], func(m, d []byte) []byte {
			h, err := bls.HashToG2(m, d)
			must(err)
			var s bls.G2Affine
			s.ScalarMultiplication(&h, sk)
			o := s.Bytes()
			return o[:]
		}}
	case "bls12-377/min_sig":
		var pk bls.G2Affine
		pk.ScalarMultiplicationBase(sk)
		b := pk.Bytes()
		return signer{b[:], func(m, d []byte) []byte {
			h, err := bls.HashToG1(m, d)
			must(err)
			var s bls.G1Affine
			s.ScalarMultiplication(&h, sk)
			o := s.Bytes()
			return o[:]
		}}
	}
	panic("unknown")
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var k keyRec
		must(json.Unmarshal(in.Bytes(), &k))
		skb, err := hex.DecodeString(k.Sk)
		must(err)
		sk := new(big.Int).SetBytes(skb)
		for _, variant := range []string{"min_pk", "min_sig"} {
			suite := suites(k.Curve, variant)
			s := mkSigner(k.Curve, variant, sk)
			pop := s.sign(s.pk, []byte("BLS_POP_"+suite+"POP_"))
			for _, m := range msgs {
				aug := append(append([]byte{}, s.pk...), m...)
				must(out.Encode(sigRec{
					Curve: k.Curve, Variant: variant, Ikm: k.Ikm, KeyInfo: k.KeyInfo, Sk: k.Sk,
					Pk:     hex.EncodeToString(s.pk),
					Pop:    hex.EncodeToString(pop),
					Msg:    hex.EncodeToString(m),
					Basic:  hex.EncodeToString(s.sign(m, []byte("BLS_SIG_"+suite+"NUL_"))),
					Aug:    hex.EncodeToString(s.sign(aug, []byte("BLS_SIG_"+suite+"AUG_"))),
					PopSig: hex.EncodeToString(s.sign(m, []byte("BLS_SIG_"+suite+"POP_"))),
				}))
			}
		}
	}
	must(in.Err())
	fmt.Fprintln(os.Stderr, "done")
}
