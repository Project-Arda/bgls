// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"

	"github.com/dchest/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	gosha3 "github.com/ethereum/go-ethereum/crypto/sha3"
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
	p1, p2 = hash64(message, sha3.Sum512, altbn_q, altbn_xToYSquared)
	return
}

func Altbn_keccak3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash32(message, EthereumSum256, altbn_q, altbn_xToYSquared)
	return
}

func Altbn_blake2b(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, blake2b.Sum512, altbn_q, altbn_xToYSquared)
	return
}

func Altbn_kang12(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, kang12_64, altbn_q, altbn_xToYSquared)
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
func Altbn_MkG1Point(x, y *big.Int) (*bn256.G1, bool) {
	xBytes, yBytes := x.Bytes(), y.Bytes()
	ret := make([]byte, 64)
	copy(ret[32-len(xBytes):], xBytes)
	copy(ret[64-len(yBytes):], yBytes)
	return new(bn256.G1).Unmarshal(ret)
}

func Altbn_HashToCurve(message []byte) *bn256.G1 {
	x, y := Altbn_keccak3(message)
	p, _ := Altbn_MkG1Point(x, y)
	return p
}

func Altbn_G1ToCoord(pt *bn256.G1) (x, y *big.Int) {
	Bytestream := pt.Marshal()
	xBytes, yBytes := Bytestream[:32], Bytestream[32:64]
	x = new(big.Int).SetBytes(xBytes)
	y = new(big.Int).SetBytes(yBytes)
	return
}

func Altbn_G2ToCoord(pt *bn256.G2) (xx, xy, yx, yy *big.Int) {
	Bytestream := pt.Marshal()
	xxBytes, xyBytes, yxBytes, yyBytes := Bytestream[:32], Bytestream[32:64], Bytestream[64:96], Bytestream[96:128]
	xx = new(big.Int).SetBytes(xxBytes)
	xy = new(big.Int).SetBytes(xyBytes)
	yx = new(big.Int).SetBytes(yxBytes)
	yy = new(big.Int).SetBytes(yyBytes)
	return
}

// Sum256 returns the SHA3-256 digest of the data.
func EthereumSum256(data []byte) (digest [32]byte) {
	h := gosha3.NewKeccak256()
	h.Write(data)
	h.Sum(digest[:0])
	return
}
