// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/sha3"
)

var bls12Q, _ = new(big.Int).SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
var bls12X, _ = new(big.Int).SetString("-0xd201000000010000", 0)
var bls12A, _ = new(big.Int).SetString("0", 10)
var bls12B, _ = new(big.Int).SetString("4", 10)
var bls12Cofactor = makeBls12Cofactor(bls12X)

func makeBls12Cofactor(x *big.Int) *big.Int {
	x.Mod(x, bls12Q)
	x.Sub(x, one)
	x.Exp(x, x, two)
	x.Div(x, three)
	return x
}

// Bls12Sha3 Hashes a message to a point on BLS12-381 using SHA3 and try and increment
// The return value is the x,y affine coordinate pair.
func Bls12Sha3(message []byte) (p1, p2 *big.Int) {
	// TODO ADD COFACTOR MULTIPLICATION
	p1, p2 = hash64(message, sha3.Sum512, bls12Q, bls12XToYSquared)
	return
}

// Bls12Blake2b Hashes a message to a point on BLS12-381 using Blake2b and try and increment
// The return value is the x,y affine coordinate pair.
func Bls12Blake2b(message []byte) (p1, p2 *big.Int) {
	// TODO ADD COFACTOR MULTIPLICATION
	p1, p2 = hash64(message, blake2b.Sum512, bls12Q, bls12XToYSquared)
	return
}

// Bls12Kang12 Hashes a message to a point on BLS12-381 using Kangaroo Twelve and try and increment
// The return value is the x,y affine coordinate pair.
func Bls12Kang12(message []byte) (p1, p2 *big.Int) {
	// TODO ADD COFACTOR MULTIPLICATION
	p1, p2 = hash64(message, kang12_64, bls12Q, bls12XToYSquared)
	return
}

func bls12XToYSquared(x *big.Int) *big.Int {
	result := new(big.Int)
	result.Exp(x, three, bls12Q)
	result.Add(result, bls12B)
	return result
}
