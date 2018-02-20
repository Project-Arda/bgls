// Copyright (C) 2016 Jeremiah Andrews
// distributed under GNU GPLv3 license

package bgls

import (
	"math/big"

	"github.com/dchest/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"golang.org/x/crypto/sha3"
)

//curve specific constants
var altbn_b = big.NewInt(3)
var altbn_q, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

//precomputed ζ = (-1 + sqrt(-3))/2 in Fq
var altbn_ζ, _ = new(big.Int).SetString("2203960485148121921418603742825762020974279258880205651966", 10)

//precomputed sqrt(-3) in Fq
var altbn_sqrtn3, _ = new(big.Int).SetString("4407920970296243842837207485651524041948558517760411303933", 10)

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
