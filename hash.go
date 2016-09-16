// Copyright (C) 2016 Jeremiah Andrews
// distributed under GNU GPLv3 license

package bgls

import (
	"crypto/rand"

	"golang.org/x/crypto/bn256"

	"github.com/dchest/blake2b"

	"math/big"
)

//curve specific constants
var b = big.NewInt(3)
var q, _ = new(big.Int).SetString("65000549695646603732796438742359905742825358107623003571877145026864184071783", 10)

//precomputed ζ = (-1 + sqrt(-3))/2 in Fq
var ζ, _ = new(big.Int).SetString("4985783334309134261147736404674766913742361673560802634030", 10)

//precomputed sqrt(-3) in Fq
var sqrtn3, _ = new(big.Int).SetString("9971566668618268522295472809349533827484723347121605268061", 10)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)
var three = big.NewInt(3)
var four = big.NewInt(4)
var minusOne = big.NewInt(-1)

// a^((q-1)/2) mod q
func isQuadRes(a *big.Int) int64 {
	if a == zero {
		return 0
	}
	pMinusOne := new(big.Int).Add(q, minusOne)
	res := new(big.Int).Div(pMinusOne, two)
	res.Exp(a, res, q)
	var x = new(big.Int)
	x.Add(res, one)
	x.Mod(x, q)
	if x.Sign() == 0 {
		return -1
	}
	return 1
}

//generates a random member of Fq such that it is a square
func randSquare() *big.Int {
	var r, _ = rand.Int(rand.Reader, q)
	return r.Exp(r, two, q)
}

//masks x with a random square in Fq, to avoid timing attacks
func maskedQuadRes(k *big.Int) int64 {
	var r = randSquare()
	r.Mul(r, k)
	r.Mod(r, q)
	return isQuadRes(r)
}

//checks that (x^3 + b) is a square in Fq
func chkPoint(x *big.Int) int64 {
	x3pb := new(big.Int).Exp(x, three, q)
	x3pb.Add(x3pb, b)
	x3pb.Mod(x3pb, q)
	return maskedQuadRes(x3pb)
}

//Shallue - van de Woestijne encoding
//from "Indifferentiable Hashing to Barreto–Naehrig Curves"
func sw(t *big.Int) (*bn256.G1, bool) {
	var x [3]*big.Int

	//w = sqrt(-3)*t / (1 + b + t^2)
	w := new(big.Int)
	w.Exp(t, two, q)
	w.Add(w, b)
	w.Add(w, one)
	w.ModInverse(w, q)
	w.Mul(w, t)
	w.Mul(w, sqrtn3)
	w.Mod(w, q)

	//x[0] = (-1 + sqrt(-3))/2 - t*w
	x[0] = new(big.Int)
	x[0].Mul(t, w)
	x[0].Mod(x[0], q)
	x[0].Neg(x[0])
	x[0].Mod(x[0], q)
	x[0].Add(x[0], ζ)
	x[0].Mod(x[0], q)

	//x[1] = -1 - x[1]
	x[1] = new(big.Int)
	x[1].Neg(x[0])
	x[1].Add(x[1], minusOne)
	x[1].Mod(x[1], q)

	//x[2] = 1 + 1/w^2
	x[2] = new(big.Int)
	x[2].Exp(w, two, q)
	x[2].ModInverse(x[2], q)
	x[2].Add(x[2], one)
	x[2].Mod(x[2], q)

	//i = first x[i] such that (x^3 + b) is square
	i := (((chkPoint(x[0]) - 1) * chkPoint(x[1])) + 3) % 3
	xr := x[i]

	//y = quadRes(t) * sqrt(x^3 + b)
	yr := new(big.Int)
	yr.Exp(xr, three, q)
	yr.Add(yr, b)
	yr = sqrt(yr)
	yr.Mul(yr, big.NewInt(maskedQuadRes(t)))
	yr.Mod(yr, q)

	return mkPoint(xr, yr)
}

//sqrt(b) mod q = b^((q+1)/4) mod q
func sqrt(b *big.Int) *big.Int {
	z := new(big.Int)
	z.Add(q, one)
	z.Div(z, four)
	z.Exp(b, z, q)
	return z
}

//copied from bn256.G1.Marshal (modified)
//copies points into []byte and unmarshals to get around curvePoint not being exported
func mkPoint(x, y *big.Int) (*bn256.G1, bool) {
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	ret := make([]byte, 64)
	copy(ret[32-len(xBytes):], xBytes)
	copy(ret[64-len(yBytes):], yBytes)
	return new(bn256.G1).Unmarshal(ret)
}

//uses 512bit hash to map message to two 256bit ints mod q
func hash(message []byte) (h1, h2 *big.Int) {
	h := blake2b.Sum512(message)
	h1 = new(big.Int)
	h1.SetBytes(h[:32])
	h1.Mod(h1, q)
	h2 = new(big.Int)
	h2.SetBytes(h[32:])
	h2.Mod(h2, q)
	return
}

//HashToCurve hashes an arbitrary byte array into a curve point on G1
//uses 512bit output of blake2b to generate and combine two G1 points
//implements http://www.di.ens.fr/~fouque/pub/latincrypt12.pdf for bn256
func HashToCurve(message []byte) (*bn256.G1, bool) {
	var h1, h2 = hash(message)
	var p1, res1 = sw(h1)
	if !res1 {
		return nil, res1
	}
	var p2, res2 = sw(h2)
	if !res2 {
		return nil, res2
	}
	return new(bn256.G1).Add(p1, p2), true
}
