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

func (pt *bls12Point1) Add(otherPt Point1) (Point1, bool) {
	g1Copy, _ := pt.Copy().(*bls12Point1)
	if other, ok := (otherPt).(*bls12Point1); ok {
		sum := g1Copy.point.Add(other.point).(*bls12.G1)
		ret := &bls12Point1{sum}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point1) Copy() Point1 {
	result := bls12Point1{pt.point.Copy().(*bls12.G1)}
	return &result
}

func (pt *bls12Point1) Equals(otherPt Point1) bool {
	if other, ok := (otherPt).(*bls12Point1); ok {
		return pt.point.Equal(other.point)
	}
	return false
}

func (pt *bls12Point1) Marshal() []byte {
	return pt.point.Marshal()
}

// TODO Make this match ebfull/pairing marshalling.
func (pt *bls12Point1) MarshalUncompressed() []byte {
	return pt.point.MarshalUncompressed()
}

func (pt *bls12Point1) Mul(scalar *big.Int) Point1 {
	prod, _ := pt.Copy().(*bls12Point1)
	prod.point.ScalarMult(new(bls12.Scalar).FromInt(scalar))
	return prod
}

func (pt *bls12Point1) ToAffineCoords() (x, y *big.Int) {
	pt.point.Normalize()
	blsx, blsy, _ := pt.point.GetXYZ()
	return blsx.ToInt()[0], blsy.ToInt()[0]
}

func (pt *bls12Point1) Pair(otherPt Point2) (PointT, bool) {
	if other, ok := (otherPt).(*bls12Point2); ok {
		p3 := new(bls12.GT).Pair(pt.point, other.point)
		ret := bls12PointT{p3}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point2) Add(otherPt Point2) (Point2, bool) {
	copy, _ := pt.Copy().(*bls12Point2)
	if other, ok := (otherPt).(*bls12Point2); ok {
		sum := copy.point.Add(other.point).(*bls12.G2)
		ret := &bls12Point2{sum}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point2) Copy() Point2 {
	result := bls12Point2{pt.point.Copy().(*bls12.G2)}
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

// TODO Make this match ebfull/pairing marshalling.
func (pt *bls12Point2) MarshalUncompressed() []byte {
	return pt.point.MarshalUncompressed()
}

func (pt *bls12Point2) Mul(scalar *big.Int) Point2 {
	prod, _ := pt.Copy().(*bls12Point2)
	prod.point.ScalarMult(new(bls12.Scalar).FromInt(scalar))
	return prod
}

func (pt *bls12Point2) ToAffineCoords() (xx, xy, yx, yy *big.Int) {
	// TODO Test this method
	Bytestream := pt.point.MarshalUncompressed()
	xxBytes, xyBytes := Bytestream[:48], Bytestream[48:96]
	yxBytes, yyBytes := Bytestream[96:144], Bytestream[144:192]
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

func (curve *bls12Curve) MakeG1Point(x, y *big.Int, check bool) (Point1, bool) {
	pt := new(bls12.G1)
	pt.SetXY(bls12.FqFromInt(x), bls12.FqFromInt(y))
	if check && !pt.Check() {
		return nil, false
	}
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
	return bls12GT
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

func (curve *bls12Curve) getG1QDivTwo() *big.Int {
	return bls12QDiv2
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
var bls12QDiv2 = new(big.Int).Div(bls12Q, two)
var bls12X, _ = new(big.Int).SetString("-0xd201000000010000", 0)
var bls12A, _ = new(big.Int).SetString("0", 10)
var bls12B, _ = new(big.Int).SetString("4", 10)

//precomputed Z = (-1 + sqrt(-3))/2 in Fq
var bls12Z, _ = new(big.Int).SetString("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350", 10)

//precomputed sqrt(-3) in Fq
var bls12SqrtNeg3, _ = new(big.Int).SetString("1586958781458431025242759403266842894121773480562120986020912974854563298150952611241517463240701", 10)
var bls12Cofactor, _ = new(big.Int).SetString("76329603384216526031706109802092473003", 10)
var bls12Order, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
var bls12GT, _ = Bls12.GetG1().Pair(Bls12.GetG2())
var bls12G1Tag1 = []byte("\x00G1_x")
var bls12G1Tag2 = []byte("\xffG1_x")

var bls12FTRoot1, _ = new(big.Int).SetString("248294325734266649657405162895821171812231848760181225578082735178502750823719347628762635478508544819911854747095", 10)
var bls12FTRoot2, _ = new(big.Int).SetString("3754115229487400743760384662840082984744650971178826659753975400945528899667118516813924993650507119217982417812692", 10)

// Fouque Tibouchi hashing as specified in https://github.com/ebfull/pairing/pull/30
func (curve *bls12Curve) HashToG1(message []byte) Point1 {
	return hashToG1BlindingAbstracted(message, false)
}

// Fouque Tibouchi hashing as specified in https://github.com/ebfull/pairing/pull/30
// This also adds time blinding
func (curve *bls12Curve) HashToG1Blind(message []byte) Point1 {
	return hashToG1BlindingAbstracted(message, true)
}

// This hashes a given message to G1, and the second parameter specifies whether
// or not to blind the computation, to prevent timing information from being leaked.
func hashToG1BlindingAbstracted(message []byte, blind bool) Point1 {
	t1Bytes := bls12G1pt1blake2b(message)
	pt1 := bls12FouqueTibouchi(t1Bytes, blind)
	t2Bytes := bls12G1pt2blake2b(message)
	pt2 := bls12FouqueTibouchi(t2Bytes, blind)

	pt1, _ = pt1.Add(pt2)
	pt1 = pt1.Mul(bls12Cofactor)
	return pt1
}

func bls12FouqueTibouchi(tBytes [64]byte, blind bool) Point1 {
	t := new(big.Int).SetBytes(tBytes[:])
	t.Mod(t, bls12Q)
	// Explicitly handle undefined t
	if t.Cmp(zero) == 0 {
		pt, _ := Bls12.MakeG1Point(zero, zero, false)
		return pt
	} else if t.Cmp(bls12FTRoot1) == 0 {
		return Bls12.GetG1()
	} else if t.Cmp(bls12FTRoot2) == 0 {
		pt := new(bls12.G1)
		g1x, g1y := Bls12.GetG1().ToAffineCoords()
		g1y.Sub(bls12Q, g1y)
		pt.SetXY(bls12.FqFromInt(g1x), bls12.FqFromInt(g1y))
		return &bls12Point1{pt}
	}

	pt, _ := fouqueTibouchiG1(Bls12, t, blind)
	return pt
}

// bls12G1pt1blake2b returns Blake2b(message || \x00 || Tag)
// This is done in correspondence to the current conversation going on at
// https://github.com/ebfull/pairing/pull/30
// A null byte is appended to the message (done inside of the tag), in
// accordance with what the rust code is currently doing.
func bls12G1pt1blake2b(message []byte) [64]byte {
	return blake2b.Sum512(append(message, bls12G1Tag1...))
}

// bls12G1pt2blake2b returns Blake2b(message || \xff || Tag)
// This is done in correspondence to the current conversation going on at
// https://github.com/ebfull/pairing/pull/30
// A null byte is appended to the message (done inside of the tag), in
// accordance with what the rust code is currently doing.
func bls12G1pt2blake2b(message []byte) [64]byte {
	return blake2b.Sum512(append(message, bls12G1Tag2...))
}
