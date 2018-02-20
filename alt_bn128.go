// Copyright (C) 2016 Jeremiah Andrews
// distributed under GNU GPLv3 license

package bgls

import (
	"math/big"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/bn256"
	"golang.org/x/crypto/sha3"
)

//curve specific constants
var altbn_b = big.NewInt(3)
var altbn_q, _ = new(big.Int).SetString("65000549695646603732796438742359905742825358107623003571877145026864184071783", 10)

//precomputed ζ = (-1 + sqrt(-3))/2 in Fq
var altbn_ζ, _ = new(big.Int).SetString("4985783334309134261147736404674766913742361673560802634030", 10)

//precomputed sqrt(-3) in Fq
var altbn_sqrtn3, _ = new(big.Int).SetString("9971566668618268522295472809349533827484723347121605268061", 10)

// Note that the cofactor in this curve is just 1

func Altbn_sha3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash(message, sha3.Sum512, altbn_q, altbn_xToYSquared)
	return
}

func Altbn_blake2b(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash(message, blake2b.Sum512, altbn_q, altbn_xToYSquared)
	return
}

func Altbn_kang12(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash(message, kang12, altbn_q, altbn_xToYSquared)
	return
}

func altbn_xToYSquared(x *big.Int) *big.Int {
	result := new(big.Int)
	result.Exp(x, three, altbn_q)
	result.Add(result, altbn_b)
	return result
}

//copied from bn256.G1.Marshal (modified)
//copies points into []byte and unmarshals to get around curvePoint not being exported
func mkAltBnPoint(x, y *big.Int) (*bn256.G1, bool) {
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	ret := make([]byte, 64)
	copy(ret[32-len(xBytes):], xBytes)
	copy(ret[64-len(yBytes):], yBytes)
	return new(bn256.G1).Unmarshal(ret)
}

func Altbn_HashToCurve(message []byte) *bn256.G1 {
	x, y := Altbn_sha3(message)
	p, _ := mkAltBnPoint(x, y)
	return p
}
