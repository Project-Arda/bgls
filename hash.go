// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"

	"github.com/mimoo/GoKangarooTwelve/K12"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)
var three = big.NewInt(3)
var four = big.NewInt(4)

// 64 byte kangaroo twelve hash
func kang12_64(messageDat []byte) [64]byte {
	inputByte := make([]byte, 1)
	hashFunc := K12.NewK12(inputByte)
	hashFunc.Write(messageDat)
	out := make([]byte, 64)
	hashFunc.Read(out)
	x := [64]byte{}
	copy(x[:], out[:64])
	return x
}

// 64 byte hash
func tryAndIncrement64(message []byte, hashfunc func(message []byte) [64]byte, curve CurveSystem) (px, py *big.Int) {
	c := 0
	px = new(big.Int)
	py = new(big.Int)
	q := curve.getG1Q()
	for {
		h := hashfunc(append(message, byte(c)))
		c++
		px.SetBytes(h[:48])
		px.Mod(px, q)
		ySqr := curve.g1XToYSquared(px)
		root := calcQuadRes(ySqr, q)
		rootSqr := new(big.Int).Exp(root, two, q)
		if rootSqr.Cmp(ySqr) == 0 {
			other_root := py.Sub(q, py)
			// Set root to the canonical square root.
			root, other_root = sortBigInts(root, other_root)
			// Use the canonical root for py, unless the cofactor is one, in which case
			// use an extra bit to determine parity.
			py = root
			if curve.getG1Cofactor().Cmp(one) == 0 {
				signY := int(h[48]) % 2
				if signY == 1 {
					py = other_root
					break
				}
			}
			break
		}
	}
	return
}

func sortBigInts(b1 *big.Int, b2 *big.Int) (*big.Int, *big.Int) {
	if b1.Cmp(b2) > 0 {
		return b2, b1
	}
	return b1, b2
}

// Try and Increment hashing that is meant to comply with the standards we are using in the solidity contract.
// This is not recommended for use anywhere else.
func tryAndIncrementEvm(message []byte, hashfunc func(message []byte) [32]byte, curve CurveSystem) (px, py *big.Int) {
	c := 0
	px = new(big.Int)
	py = new(big.Int)
	q := curve.getG1Q()
	for {
		h := hashfunc(append(message, byte(c)))
		c++
		px.SetBytes(h[:32])
		px.Mod(px, q)
		ySqr := curve.g1XToYSquared(px)
		root := calcQuadRes(ySqr, q)
		rootSqr := new(big.Int).Exp(root, two, q)
		if rootSqr.Cmp(ySqr) == 0 {
			py = root
			signY := hashfunc(append(message, byte(255)))[31] % 2
			if signY == 1 {
				py.Sub(q, py)
			}
			break
		}
	}
	return
}

// Currently implementing first method from
// http://mathworld.wolfram.com/QuadraticResidue.html
// Experimentally, this seems to always return the canonical square root,
// however I haven't seen a proof of this.
func calcQuadRes(ySqr *big.Int, q *big.Int) *big.Int {
	resMod4 := new(big.Int).Mod(q, four)
	if resMod4.Cmp(three) == 0 {
		k := new(big.Int).Sub(q, three)
		k.Div(k, four)
		exp := new(big.Int).Add(k, one)
		result := new(big.Int)
		result.Exp(ySqr, exp, q)
		return result
	}
	// TODO: ADD CODE TO CALC QUADRATIC RESIDUE IN OTHER CASES
	return zero
}

// Currently implementing method from Guide to Pairing Based Cryptography, Ch 5 algorithm 18.
// This in turn is cited from "Gora Adj and Francisco Rodriguez-Henriquez.
// Square root computation over even extension fields.
// IEEE Transactions on Computers, 63(11):2829-2841, 2014"
func calcComplexQuadRes(ySqr *complexNum, q *big.Int) *complexNum {
	result := getComplexZero()
	if ySqr.im.Cmp(zero) == 0 {
		result.re = calcQuadRes(ySqr.re, q)
		return result
	}
	lambda := new(big.Int).Exp(ySqr.re, two, q)
	lambda.Add(lambda, new(big.Int).Exp(ySqr.im, two, q))
	lambda = calcQuadRes(lambda, q)
	invtwo := new(big.Int).ModInverse(two, q)
	delta := new(big.Int).Add(ySqr.re, lambda)
	delta.Mod(delta, q)
	delta.Mul(delta, invtwo)
	delta.Mod(delta, q)
	if !isQuadRes(delta, q) {
		delta = new(big.Int).Sub(ySqr.re, lambda)
		delta.Mul(delta, invtwo)
		delta.Mod(delta, q)
	}
	result.re = calcQuadRes(delta, q)
	invRe := new(big.Int).ModInverse(result.re, q)
	result.im.Mul(invRe, invtwo)
	result.im.Mod(result.im, q)
	result.im.Mul(result.im, ySqr.im)
	result.im.Mod(result.im, q)
	result.re.Mod(result.re, q)
	return result
}

// Implement Eulers Criterion
func isQuadRes(a *big.Int, q *big.Int) bool {
	if a.Cmp(zero) == 0 {
		return true
	}
	fieldOrder := new(big.Int).Sub(q, one)
	res := new(big.Int).Div(fieldOrder, two)
	res.Exp(a, res, q)
	if res.Cmp(one) == 0 {
		return true
	}
	return false
}
