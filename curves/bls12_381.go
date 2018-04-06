// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"encoding"
	"hash"
	"math/big"

	"github.com/dis2/bls12"
	"golang.org/x/crypto/blake2b"
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

func (pt *bls12Point1) Add(otherPt Point) (Point, bool) {
	g1Copy, _ := pt.Copy().(*bls12Point1)
	if other, ok := (otherPt).(*bls12Point1); ok {
		sum := g1Copy.point.Add(other.point).(*bls12.G1)
		ret := &bls12Point1{sum}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point1) Copy() Point {
	result := bls12Point1{pt.point.Copy().(*bls12.G1)}
	return &result
}

func (pt *bls12Point1) Equals(otherPt Point) bool {
	if other, ok := (otherPt).(*bls12Point1); ok {
		return pt.point.Equal(other.point)
	}
	return false
}

// TODO Make this match ebfull/pairing marshalling.
func (pt *bls12Point1) Marshal() []byte {
	return pt.point.Marshal()
}

// TODO Make this match ebfull/pairing marshalling.
func (pt *bls12Point1) MarshalUncompressed() []byte {
	return pt.point.MarshalUncompressed()
}

func (pt *bls12Point1) Mul(scalar *big.Int) Point {
	prod, _ := pt.Copy().(*bls12Point1)
	cmp := scalar.Cmp(zero)
	if cmp < 0 {
		prod = prod.Negate()
		scalar.Mul(scalar, big.NewInt(-1))
	} else if cmp == 0 {
		return Bls12.GetG1Infinity()
	}
	prod.point.ScalarMult(new(bls12.Scalar).FromInt(scalar))
	return prod
}

func (pt *bls12Point1) Negate() *bls12Point1 {
	coords := pt.ToAffineCoords()
	coords[1].Sub(bls12Q, coords[1])
	newPt, _ := Bls12.MakeG1Point(coords, false)
	return newPt.(*bls12Point1)
}

// ToAffineCoords returns the affine coordinate representation of the point
// in the form: [X, Y]
func (pt *bls12Point1) ToAffineCoords() []*big.Int {
	// Upstream library uses projective space
	pt.point.Normalize()
	blsx, blsy, _ := pt.point.GetXYZ()
	return []*big.Int{blsx.ToInt()[0], blsy.ToInt()[0]}
}

func (pt *bls12Point2) Add(otherPt Point) (Point, bool) {
	copy, _ := pt.Copy().(*bls12Point2)
	if other, ok := (otherPt).(*bls12Point2); ok {
		sum := copy.point.Add(other.point).(*bls12.G2)
		ret := &bls12Point2{sum}
		return ret, true
	}
	return nil, false
}

func (pt *bls12Point2) Copy() Point {
	result := bls12Point2{pt.point.Copy().(*bls12.G2)}
	return &result
}

func (pt *bls12Point2) Equals(otherPt Point) bool {
	if other, ok := (otherPt).(*bls12Point2); ok {
		return pt.point.Equal(other.point)
	}
	return false
}

// TODO Make this match ebfull/pairing marshalling.
func (pt *bls12Point2) Marshal() []byte {
	return pt.point.Marshal()
}

// TODO Make this match ebfull/pairing marshalling.
func (pt *bls12Point2) MarshalUncompressed() []byte {
	return pt.point.MarshalUncompressed()
}

func (pt *bls12Point2) Mul(scalar *big.Int) Point {
	prod, _ := pt.Copy().(*bls12Point2)
	cmp := scalar.Cmp(zero)
	if cmp < 0 {
		prod = prod.Negate()
		scalar.Mul(scalar, big.NewInt(-1))
	} else if cmp == 0 {
		return Bls12.GetG2Infinity()
	}
	prod.point.ScalarMult(new(bls12.Scalar).FromInt(scalar))
	return prod
}

func (pt *bls12Point2) Negate() *bls12Point2 {
	coords := pt.ToAffineCoords()
	coords[2].Sub(bls12Q, coords[2])
	coords[3].Sub(bls12Q, coords[3])
	newPt, _ := Bls12.MakeG2Point(coords, false)
	return newPt.(*bls12Point2)
}

// ToAffineCoords returns the affine coordinate representation of the point
// in the form: [x0, x1, y0, y1], where X = x0 * u + x1, and Y = y0 * u + y1
func (pt *bls12Point2) ToAffineCoords() []*big.Int {
	Bytestream := pt.point.MarshalUncompressed()
	x0Bytes, x1Bytes := Bytestream[:48], Bytestream[48:96]
	y0Bytes, y1Bytes := Bytestream[96:144], Bytestream[144:192]
	x0 := new(big.Int).SetBytes(x0Bytes)
	x1 := new(big.Int).SetBytes(x1Bytes)
	y0 := new(big.Int).SetBytes(y0Bytes)
	y1 := new(big.Int).SetBytes(y1Bytes)
	return []*big.Int{x0, x1, y0, y1}
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

func (curve *bls12Curve) Name() string {
	return "bls12"
}

// MakeG2Point expects coords to be of the form: [X, Y]
func (curve *bls12Curve) MakeG1Point(coords []*big.Int, check bool) (Point, bool) {
	if len(coords) != 2 {
		return nil, false
	}
	pt := new(bls12.G1)
	pt.SetXY(bls12.FqFromInt(coords[0]), bls12.FqFromInt(coords[1]))
	if check && !pt.Check() {
		return nil, false
	}
	return &bls12Point1{pt}, true
}

// MakeG2Point expects coords to be of the form: [x0, x1, y0, y1],
// where X = x0 * u + x1, and Y = y0 * u + y1
func (curve *bls12Curve) MakeG2Point(coords []*big.Int, check bool) (Point, bool) {
	if len(coords) != 4 {
		return nil, false
	}
	pt := new(bls12.G2)
	x := new(bls12.Fq2)
	// Underlying library expects coordinates in the form [x1, x0] amd [y1, y0]
	x.FromInt([]*big.Int{coords[1], coords[0]})
	y := new(bls12.Fq2)
	y.FromInt([]*big.Int{coords[3], coords[2]})
	pt.SetXY(x, y)
	if check && !pt.Check() {
		return nil, false
	}
	return &bls12Point2{pt}, true
}

func (curve *bls12Curve) Pair(pt1 Point, pt2 Point) (PointT, bool) {
	p1, ok1 := pt1.(*bls12Point1)
	if p2, ok2 := pt2.(*bls12Point2); ok1 && ok2 {
		p3 := new(bls12.GT).Pair(p1.point, p2.point)
		ret := bls12PointT{p3}
		return ret, true
	}
	return nil, false
}

func (curve *bls12Curve) PairingProduct(pts1 []Point, pts2 []Point) (PointT, bool) {
	return concurrentPairingProduct(curve, pts1, pts2)
}

func (curve *bls12Curve) UnmarshalG1(data []byte) (Point, bool) {
	if len(data) != 48 && len(data) != 96 {
		return nil, false
	}
	result := new(bls12.G1)
	success := result.Unmarshal(data)
	if success == nil || !result.Check() {
		return nil, false
	}
	return &bls12Point1{result}, true
}

func (curve *bls12Curve) UnmarshalG2(data []byte) (Point, bool) {
	if len(data) != 96 && len(data) != 192 {
		return nil, false
	}
	result := new(bls12.G2)
	success := result.Unmarshal(data)
	if success == nil || !result.Check() {
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

func (curve *bls12Curve) GetG1() Point {
	return &bls12Point1{bls12.G1One()}
}

func (curve *bls12Curve) GetG2() Point {
	return &bls12Point2{bls12.G2One()}
}

func (curve *bls12Curve) GetGT() PointT {
	return bls12GT
}

func (curve *bls12Curve) GetG1Infinity() Point {
	return &bls12Point1{bls12.G1Zero()}
}

func (curve *bls12Curve) GetG2Infinity() Point {
	return &bls12Point2{bls12.G2Zero()}
}

func (curve *bls12Curve) GetGTIdentity() PointT {
	return bls12GTIdentity
}

func (curve *bls12Curve) getG1A() *big.Int {
	return zero
}

func (curve *bls12Curve) getG1B() *big.Int {
	return bls12B
}

func (curve *bls12Curve) GetG1Q() *big.Int {
	return bls12Q
}

func (curve *bls12Curve) getG1Cofactor() *big.Int {
	return bls12Cofactor
}

func (curve *bls12Curve) g1XToYSquared(x *big.Int) *big.Int {
	y := bls12.FqFromInt(x).Y2FromX(nil)
	return y.ToInt()[0]
}

func (curve *bls12Curve) GetG1Order() *big.Int {
	return bls12Order
}

func (curve *bls12Curve) getFTHashParams() (*big.Int, *big.Int) {
	return bls12SwencSqrtNegThree, bls12SwencSqrtNegThreeMinusOneOverTwo
}

var bls12Q, _ = new(big.Int).SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
var bls12X, _ = new(big.Int).SetString("-0xd201000000010000", 0)
var bls12A, _ = new(big.Int).SetString("0", 10)
var bls12B, _ = new(big.Int).SetString("4", 10)

//precomputed bls12SwencSqrtNegThreeMinusOneOverTwo = (-1 + sqrt(-3))/2 in Fq
var bls12SwencSqrtNegThreeMinusOneOverTwo, _ = new(big.Int).SetString("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350", 10)

//precomputed bls12SwencSqrtNegThree in Fq
var bls12SwencSqrtNegThree, _ = new(big.Int).SetString("1586958781458431025242759403266842894121773480562120986020912974854563298150952611241517463240701", 10)
var bls12Cofactor, _ = new(big.Int).SetString("76329603384216526031706109802092473003", 10)
var bls12Order, _ = new(big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
var bls12GT, _ = Bls12.Pair(Bls12.GetG1(), Bls12.GetG2())
var bls12GTIdentity, _ = Bls12.Pair(Bls12.GetG1Infinity(), Bls12.GetG2())
var bls12G1Tag1 = []byte("G1_0")
var bls12G1Tag2 = []byte("G1_1")

var bls12FTRoot1, _ = new(big.Int).SetString("248294325734266649657405162895821171812231848760181225578082735178502750823719347628762635478508544819911854747095", 10)
var bls12FTRoot2, _ = new(big.Int).SetString("3754115229487400743760384662840082984744650971178826659753975400945528899667118516813924993650507119217982417812692", 10)

// Fouque Tibouchi hashing as specified in https://github.com/ebfull/pairing/pull/30
func (curve *bls12Curve) HashToG1(message []byte) Point {
	return hashToG1BlindingAbstracted(message, false)
}

// Fouque Tibouchi hashing as specified in https://github.com/ebfull/pairing/pull/30
// This also adds time blinding
func (curve *bls12Curve) HashToG1Blind(message []byte) Point {
	return hashToG1BlindingAbstracted(message, true)
}

// This hashes a given message to G1, and the second parameter specifies whether
// or not to blind the computation, to prevent timing information from being leaked.
func hashToG1BlindingAbstracted(message []byte, blind bool) Point {
	b2, _ := blake2b.New512(nil)
	b2Copy, _ := blake2b.New512(nil)
	b2.Write(message)
	b2State, _ := b2.(encoding.BinaryMarshaler).MarshalBinary()
	b2Copy.(encoding.BinaryUnmarshaler).UnmarshalBinary(b2State)
	t1Bytes := bls12Blake2b(b2, bls12G1Tag1)
	pt1 := bls12FouqueTibouchi(t1Bytes, blind)
	t2Bytes := bls12Blake2b(b2Copy, bls12G1Tag2)
	pt2 := bls12FouqueTibouchi(t2Bytes, blind)

	pt1, _ = pt1.Add(pt2)
	// Underlying library does cofactor multiplication implicitly
	// pt1 = pt1.Mul(bls12Cofactor)
	return pt1
}

func bls12FouqueTibouchi(tBytes []byte, blind bool) Point {
	t := new(big.Int).SetBytes(tBytes)
	t.Mod(t, bls12Q)
	// Explicitly handle degenerate cases for t
	if t.Cmp(zero) == 0 { // Hash(0) = infty
		pt := Bls12.GetG1Infinity()
		return pt
	} else if t.Cmp(bls12FTRoot1) == 0 { // encode(sqrt(-5)) = -g1
		return Bls12.GetG1()
	} else if t.Cmp(bls12FTRoot2) == 0 { // encode(-sqrt(-5)) = g1
		return Bls12.GetG1().(*bls12Point1).Negate()
	}

	pt, _ := fouqueTibouchiG1(Bls12, t, blind)
	return pt
}

// bls12Blake2b returns Blake2b(message || Tag)
// The tags with what is being used in https://github.com/ebfull/pairing/pull/30
func bls12Blake2b(blake2b hash.Hash, tag []byte) []byte {
	blake2b.Write(tag)
	return blake2b.Sum([]byte{})
}
