// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"

	"github.com/dchest/blake2b"
	"github.com/dis2/bls12"
)

type bls12Curve struct {
}

type bls12Point1 struct {
	point *bls12.G1
}

type bls12Point2 struct {
	point *bls12.G2
}

type bls12PointT struct {
	point *bls12.GT
}

// Bls12 is the instance for the bls12 curve, with all of its functions.
var Bls12 = &bls12Curve{}

func (g1Point *bls12Point1) Add(otherPoint1 Point1) (Point1, bool) {
	g1Copy, _ := g1Point.Copy().(*bls12Point1)
	if other, ok := (otherPoint1).(*bls12Point1); ok {
		sum := g1Copy.point.Add(other.point)
		ret := &bls12Point1{sum}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point1) Copy() Point1 {
	result := bls12Point1{pt.point.Copy()}
	return &result
}

func (pt *bls12Point1) Equals(otherPoint1 Point1) bool {
	if other, ok := (otherPoint1).(*bls12Point1); ok {
		return pt.point.Equal(other.point)
	}
	return false
}

func (g1Point *bls12Point1) Marshal() []byte {
	return g1Point.point.Marshal()
}

func (g1Point *bls12Point1) Mul(scalar *big.Int) Point1 {
	prod, _ := g1Point.Copy().(*bls12Point1)
	prod.point.ScalarMult(new(bls12.Scalar).FromInt(scalar))
	return prod
}

func (g1Point *bls12Point1) ToAffineCoords() (x, y *big.Int) {
	g1Point.point.Normalize()
	blsx, blsy, _ := g1Point.point.GetXYZ()
	return blsx.ToInt()[0], blsy.ToInt()[0]
}

func (g1Point *bls12Point1) Pair(g2Point Point2) (PointT, bool) {
	if other, ok := (g2Point).(*bls12Point2); ok {
		p3 := new(bls12.GT).Pair(g1Point.point, other.point)
		ret := bls12PointT{p3}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point2) Add(otherPt Point2) (Point2, bool) {
	copy, _ := pt.Copy().(*bls12Point2)
	if other, ok := (otherPt).(*bls12Point2); ok {
		sum := copy.point.Add(other.point)
		ret := &bls12Point2{sum}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point2) Copy() Point2 {
	result := bls12Point2{pt.point.Copy()}
	return &result
}

func (pt *bls12Point2) Equals(otherPt Point2) bool {
	if other, ok := (otherPt).(*bls12Point2); ok {
		return pt.point.Equal(other.point)
	}
	return false
}

func (pt *bls12Point2) Marshal() []byte {
	return pt.point.Marshal()
}

func (pt *bls12Point2) Mul(scalar *big.Int) Point2 {
	prod, _ := pt.Copy().(*bls12Point2)
	prod.point.ScalarMult(new(bls12.Scalar).FromInt(scalar))
	return prod
}

func (pt *bls12Point2) ToAffineCoords() (xx, xy, yx, yy *big.Int) {
	// TODO These constants definitely need to be adjusted
	// Currently this is just implemented to satisfy the curve interface.
	Bytestream := pt.point.Marshal()
	xxBytes, xyBytes := Bytestream[:32], Bytestream[32:64]
	yxBytes, yyBytes := Bytestream[64:96], Bytestream[96:128]
	xx = new(big.Int).SetBytes(xxBytes)
	xy = new(big.Int).SetBytes(xyBytes)
	yx = new(big.Int).SetBytes(yxBytes)
	yy = new(big.Int).SetBytes(yyBytes)
	return
}

func (pt bls12PointT) Add(otherPt PointT) (PointT, bool) {
	copy, _ := pt.Copy().(bls12PointT)
	if other, ok := (otherPt).(bls12PointT); ok {
		sum := copy.point.Add(other.point)
		ret := bls12PointT{sum}
		return ret, true
	}
	return nil, false
}

func (pt bls12PointT) Copy() PointT {
	result := bls12PointT{pt.point.Copy()}
	return result
}

func (pt bls12PointT) Equals(otherPt PointT) bool {
	if other, ok := (otherPt).(bls12PointT); ok {
		return pt.point.Equal(other.point)
	}
	return false
}

func (pt bls12PointT) Marshal() []byte {
	return pt.point.Marshal()
}

func (pt bls12PointT) Mul(scalar *big.Int) PointT {
	prod, _ := pt.Copy().(bls12PointT)
	prod.point.ScalarMult(new(bls12.Scalar).FromInt(scalar))
	return prod
}

func (curve *bls12Curve) MakeG1Point(x, y *big.Int) (Point1, bool) {
	pt := new(bls12.G1)
	pt.SetXY(bls12.FqFromInt(x), bls12.FqFromInt(y))
	// TODO need to add method to check if the point is on the curve whenever this is called.
	// In the other library, this was already checked
	return &bls12Point1{pt}, true
}

func (curve *bls12Curve) UnmarshalG1(data []byte) (Point1, bool) {
	result := new(bls12.G1)
	success := result.Unmarshal(data)
	if success == nil {
		return nil, false
	}
	return &bls12Point1{result}, true
}

func (curve *bls12Curve) UnmarshalG2(data []byte) (Point2, bool) {
	result := new(bls12.G2)
	success := result.Unmarshal(data)
	if success == nil {
		return nil, false
	}
	return &bls12Point2{result}, true
}

func (curve *bls12Curve) UnmarshalGT(data []byte) (PointT, bool) {
	result := new(bls12.GT)
	success := result.Unmarshal(data)
	if success == nil {
		return nil, false
	}
	return &bls12PointT{result}, true
}

func (curve *bls12Curve) GetG1() Point1 {
	return &bls12Point1{bls12.G1One()}
}

func (curve *bls12Curve) GetG2() Point2 {
	return &bls12Point2{bls12.G2One()}
}

func (curve *bls12Curve) GetGT() PointT {
	return GT
}

func (curve *bls12Curve) getG1A() *big.Int {
	return zero
}

func (curve *bls12Curve) getG1B() *big.Int {
	return bls12B
}

func (curve *bls12Curve) getG1Q() *big.Int {
	return bls12Q
}

func (curve *bls12Curve) getG1Cofactor() *big.Int {
	return bls12Cofactor
}

func (curve *bls12Curve) g1XToYSquared(x *big.Int) *big.Int {
	y := bls12.FqFromInt(x).Y2FromX(nil)
	return y.ToInt()[0]
}

func (curve *bls12Curve) getG1Order() *big.Int {
	return bls12Order
}

func (curve *bls12Curve) getFTHashParams() (*big.Int, *big.Int) {
	return bls12SqrtNeg3, bls12Z
}

var bls12Q, _ = new(big.Int).SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
var bls12X, _ = new(big.Int).SetString("-0xd201000000010000", 0)
var bls12A, _ = new(big.Int).SetString("0", 10)
var bls12B, _ = new(big.Int).SetString("4", 10)

//precomputed Z = (-1 + sqrt(-3))/2 in Fq
var bls12Z, _ = new(big.Int).SetString("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350", 10)

//precomputed sqrt(-3) in Fq
var bls12SqrtNeg3, _ = new(big.Int).SetString("1586958781458431025242759403266842894121773480562120986020912974854563298150952611241517463240701", 10)
var bls12Cofactor = makeBlsCofactor(bls12X)
var bls12Order, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
var GT, _ = Bls12.GetG1().Pair(Bls12.GetG2())

func makeBlsCofactor(x *big.Int) *big.Int {
	x.Mod(x, bls12Q)
	x.Sub(x, one)
	x.Exp(x, x, two)
	x.Div(x, three)
	return x
}

// This is currently a filler method so I can get the initial structure of bls12 committed.
// This is going to be Foque Tibouchi hashing that is compatible with ebfull/pairings
func (curve *bls12Curve) HashToG1(message []byte) Point1 {
	x, y := tryAndIncrement64(message, blake2b.Sum512, Bls12)
	p, _ := curve.MakeG1Point(x, y)
	return p
}

// // Bls12Sha3 Hashes a message to a point on BLS12-381 using SHA3 and try and increment
// // The return value is the x,y affine coordinate pair.
// func Bls12Sha3(message []byte) (p1, p2 *big.Int) {
// 	// TODO ADD COFACTOR MULTIPLICATION
// 	p1, p2 = hash64(message, sha3.Sum512, bls12Q, bls12XToYSquared)
// 	return
// }
//
// // Bls12Blake2b Hashes a message to a point on BLS12-381 using Blake2b and try and increment
// // The return value is the x,y affine coordinate pair.
// func Bls12Blake2b(message []byte) (p1, p2 *big.Int) {
// 	// TODO ADD COFACTOR MULTIPLICATION
// 	p1, p2 = hash64(message, blake2b.Sum512, bls12Q, bls12XToYSquared)
// 	return
// }
//
// // Bls12Kang12 Hashes a message to a point on BLS12-381 using Kangaroo Twelve and try and increment
// // The return value is the x,y affine coordinate pair.
// func Bls12Kang12(message []byte) (p1, p2 *big.Int) {
// 	// TODO ADD COFACTOR MULTIPLICATION
// 	p1, p2 = hash64(message, kang12_64, bls12Q, bls12XToYSquared)
// 	return
// }

// func bls12XToYSquared(x *big.Int) *big.Int {
// 	result := new(big.Int)
// 	result.Exp(x, three, bls12Q)
// 	result.Add(result, bls12B)
// 	return result
// }
