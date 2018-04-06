// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"crypto/rand"
	"math/big"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)
var three = big.NewInt(3)
var four = big.NewInt(4)

// 64 byte hash
func tryAndIncrement64(message []byte, hashfunc func(message []byte) [64]byte, curve CurveSystem) (px, py *big.Int) {
	counter := []byte{byte(0)}
	px = new(big.Int)
	py = new(big.Int)
	q := curve.GetG1Q()
	for {
		h := hashfunc(append(counter, message...))
		counter[0]++
		px.SetBytes(h[:48])
		px.Mod(px, q)
		ySqr := curve.g1XToYSquared(px)
		root := calcQuadRes(ySqr, q)
		rootSqr := new(big.Int).Exp(root, two, q)
		if rootSqr.Cmp(ySqr) == 0 {
			otherRoot := py.Sub(q, py)
			// Set root to the canonical square root.
			root, otherRoot = sortBigInts(root, otherRoot)
			// Use the canonical root for py, unless the cofactor is one, in which case
			// use an extra bit to determine parity.
			py = root
			if curve.getG1Cofactor().Cmp(one) == 0 {
				signY := int(h[48]) % 2
				if signY == 1 {
					py = otherRoot
					break
				}
			}
			break
		}
	}
	return
}

// Try and Increment hashing that is meant to comply with the standards we are using in the solidity contract.
// This is not recommended for use anywhere else.
func tryAndIncrementEvm(message []byte, hashfunc func(message []byte) [32]byte, curve CurveSystem) (px, py *big.Int) {
	counter := []byte{byte(0)}
	px = new(big.Int)
	py = new(big.Int)
	q := curve.GetG1Q()
	for {
		h := hashfunc(append(counter, message...))
		counter[0]++
		px.SetBytes(h[:32])
		px.Mod(px, q)
		ySqr := curve.g1XToYSquared(px)
		root := calcQuadRes(ySqr, q)
		rootSqr := new(big.Int).Exp(root, two, q)
		if rootSqr.Cmp(ySqr) == 0 {
			py = root
			counter[0] = byte(255)
			signY := hashfunc(append(counter, message...))[31] % 2
			if signY == 1 {
				py.Sub(q, py)
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

func fouqueTibouchiG1(curve CurveSystem, t *big.Int, blind bool) (Point, bool) {
	pt, ok := sw(curve, t, blind)
	if !ok {
		return nil, false
	}
	pt = pt.Mul(curve.getG1Cofactor())
	return pt, true
}

// Shallue - van de Woestijne encoding
// from "Indifferentiable Hashing to Barreto–Naehrig Curves"
func sw(curve CurveSystem, t *big.Int, blind bool) (Point, bool) {
	var x [3]*big.Int
	b := curve.getG1B()
	q := curve.GetG1Q()
	rootNeg3, neg1SubRootNeg3 := curve.getFTHashParams()

	//w = sqrt(-3)*t / (1 + b + t^2)
	w := new(big.Int)
	w.Exp(t, two, q)
	w.Add(w, one)
	w.Add(w, b)
	w.ModInverse(w, q)
	w.Mul(w, t)
	w.Mod(w, q)
	w.Mul(w, rootNeg3)
	w.Mod(w, q)

	alpha := int64(0)
	beta := int64(0)
	var i int

	for i = 0; i < 3; i++ {
		if i == 0 {
			//x[0] = (-1 + sqrt(-3))/2 - t*w
			x[0] = new(big.Int)
			x[0].Mul(t, w)
			x[0].Mod(x[0], q)
			x[0].Sub(q, x[0])
			x[0].Add(x[0], neg1SubRootNeg3)
			x[0].Mod(x[0], q)

			// If blinding isn't needed, utilize conditional branches.
			alpha = chkPoint(x[0], curve, q, blind)
			if !blind && alpha == 1 {
				break
			}
		} else if i == 1 {
			//x[1] = -1 - x[1]
			x[1] = new(big.Int)
			x[1].Neg(x[0])
			x[1].Sub(x[1], one)
			x[1].Mod(x[1], q)

			beta = chkPoint(x[1], curve, q, blind)
			if !blind && beta == 1 {
				break
			}
		} else {
			//x[2] = 1 + 1/w^2
			x[2] = new(big.Int)
			x[2].Exp(w, two, q)
			x[2].ModInverse(x[2], q)
			x[2].Add(x[2], one)
			x[2].Mod(x[2], q)
			break
		}
	}

	//i = first x[i] such that (x^3 + b) is square
	if blind {
		i = int((((alpha - 1) * beta) + 3) % 3)
	}

	// TODO Add blinded form of this
	y := calcQuadRes(curve.g1XToYSquared(x[i]), q)
	if parity(y, q) != parity(t, q) {
		y.Sub(q, y)
	}
	// Check is set to false since its guaranteed to be on the curve
	return curve.MakeG1Point([]*big.Int{x[i], y}, false)
}

func parity(x *big.Int, q *big.Int) bool {
	neg := new(big.Int).Sub(q, x)
	return x.Cmp(neg) > 0
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

//generates a random member of Fq such that it is a square
func randSquare(q *big.Int) *big.Int {
	var r, _ = rand.Int(rand.Reader, q)
	return r.Exp(r, two, q)
}

// If blind is true, this blinds k with a random square in Fq,
// and then returns square root. This can be done to limit timing leakage.
// This returns the quadratic character of k.
func quadraticCharacter(k *big.Int, q *big.Int, blind bool) int64 {
	r := k
	if blind {
		r = randSquare(q)
		r.Mul(r, k)
		r.Mod(r, q)
	}
	res := isQuadRes(r, q)
	if res {
		return 1
	}
	return -1
}

//checks that (x^3 + b) is a square in Fq
func chkPoint(x *big.Int, curve CurveSystem, q *big.Int, mask bool) int64 {
	return quadraticCharacter(curve.g1XToYSquared(x), q, mask)
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
