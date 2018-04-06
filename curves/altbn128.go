// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"bytes"
	"math/big"

	"github.com/dchest/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	gosha3 "github.com/ethereum/go-ethereum/crypto/sha3"
	"golang.org/x/crypto/sha3"
)

type altbn128 struct {
}

type altbn128Point1 struct {
	point *bn256.G1
}

type altbn128Point2 struct {
	point *bn256.G2
}

type altbn128PointT struct {
	point *bn256.GT
}

// Altbn128Inst is the instance for the altbn128 curve, with all of its functions.
var Altbn128 = &altbn128{}

// Returns the name of the curve
func (curve *altbn128) Name() string {
	return "altbn128"
}

// MakeG1Point copies points into []byte and unmarshals to get around curvePoint not being exported
// Check does nothing here, because the upstream library always
// ensures that the point is on the curve.
func (curve *altbn128) MakeG1Point(coords []*big.Int, check bool) (Point, bool) {
	if len(coords) != 2 {
		return nil, false
	}
	xBytes, yBytes := coords[0].Bytes(), coords[1].Bytes()
	ret := make([]byte, 64)
	copy(ret[32-len(xBytes):], xBytes)
	copy(ret[64-len(yBytes):], yBytes)
	result := new(bn256.G1)
	var ok error
	_, ok = result.Unmarshal(ret)
	if ok != nil {
		return nil, false
	}
	return &altbn128Point1{result}, true
}

func (g1Point *altbn128Point1) Add(otherPoint1 Point) (Point, bool) {
	if other, ok := (otherPoint1).(*altbn128Point1); ok {
		sum := new(bn256.G1).Add(g1Point.point, other.point)
		ret := &altbn128Point1{sum}
		return ret, true
	}
	return nil, false
}

func (g1Point *altbn128Point1) Copy() Point {
	result := new(bn256.G1)
	result.Unmarshal(g1Point.point.Marshal())
	return &altbn128Point1{result}
}

func (g1Point *altbn128Point1) Equals(otherPoint1 Point) bool {
	if other, ok := (otherPoint1).(*altbn128Point1); ok {
		return bytes.Equal(g1Point.point.Marshal(), other.point.Marshal())
	}
	return false
}

func (g1Point *altbn128Point1) Marshal() []byte {
	coords := g1Point.ToAffineCoords()
	xBytes := pad32Bytes(coords[0].Bytes())
	coords[1].Mul(coords[1], two)
	if coords[1].Cmp(altbnG1Q) == 1 {
		xBytes[0] += 128
	}
	return xBytes
}

func (g1Point *altbn128Point1) MarshalUncompressed() []byte {
	return g1Point.point.Marshal()
}

func pad32Bytes(xBytes []byte) []byte {
	if len(xBytes) < 32 {
		offset := 32 - len(xBytes)
		rawBytes := make([]byte, 32, 32)
		for i := 0; i < len(xBytes); i++ {
			rawBytes[i+offset] = xBytes[i]
		}
		return rawBytes
	}
	return xBytes
}

func (g1Point *altbn128Point1) Mul(scalar *big.Int) Point {
	scalar2 := new(big.Int)
	cmp := scalar.Cmp(zero)
	if cmp < 0 {
		g1Point = g1Point.Negate()
		scalar2.Mul(scalar, big.NewInt(-1))
	} else if cmp == 0 {
		return Altbn128.GetG1Infinity()
	} else {
		scalar2 = scalar
	}
	prod := new(bn256.G1).ScalarMult(g1Point.point, scalar2)
	ret := &altbn128Point1{prod}
	return ret
}

func (g1Point *altbn128Point1) Negate() *altbn128Point1 {
	coords := g1Point.ToAffineCoords()
	coords[1].Sub(altbnG1Q, coords[1])
	newPt, _ := Altbn128.MakeG1Point(coords, false)
	return newPt.(*altbn128Point1)
}

func (curve *altbn128) Pair(g1Point Point, g2Point Point) (PointT, bool) {
	pt1, ok := g1Point.(*altbn128Point1)
	if !ok {
		return nil, false
	}
	if pt2, ok := (g2Point).(*altbn128Point2); ok {
		p3 := bn256.Pair(pt1.point, pt2.point)
		ret := altbn128PointT{p3}
		return ret, true
	}
	return nil, false
}

func (curve *altbn128) PairingProduct(g1Points []Point, g2Points []Point) (PointT, bool) {
	return concurrentPairingProduct(curve, g1Points, g2Points)
}

// ToAffineCoords returns the affine coordinate representation of the point
// in the form: [X, Y]
func (g1Point *altbn128Point1) ToAffineCoords() []*big.Int {
	Bytestream := g1Point.point.Marshal()
	xBytes, yBytes := Bytestream[:32], Bytestream[32:64]
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return []*big.Int{x, y}
}

// MakeG2Point expects coords to be of the form: [x0, x1, y0, y1],
// where X = x0 * i + x1, and Y = y0 * i + y1
// check does nothing, since the upstream repository always checks if the point
// is on the curve
func (curve *altbn128) MakeG2Point(coords []*big.Int, check bool) (Point, bool) {
	if len(coords) != 4 {
		return nil, false
	}
	x0Bytes, x1Bytes := pad32Bytes(coords[0].Bytes()), pad32Bytes(coords[1].Bytes())
	y0Bytes, y1Bytes := pad32Bytes(coords[2].Bytes()), pad32Bytes(coords[3].Bytes())
	ret := make([]byte, 128)
	copy(ret[:32], x0Bytes)
	copy(ret[32:], x1Bytes)
	copy(ret[64:], y0Bytes)
	copy(ret[96:], y1Bytes)
	result := new(bn256.G2)
	var ok error
	_, ok = result.Unmarshal(ret)
	if ok != nil {
		return nil, false
	}
	return &altbn128Point2{result}, true
}

func (g2Point *altbn128Point2) Add(otherPoint2 Point) (Point, bool) {
	if other, ok := (otherPoint2).(*altbn128Point2); ok {
		sum := new(bn256.G2).Add(g2Point.point, other.point)
		ret := &altbn128Point2{sum}
		return ret, true
	}
	return nil, false
}

func (g2Point *altbn128Point2) Copy() Point {
	result := new(bn256.G2)
	result.Unmarshal(g2Point.point.Marshal())
	return &altbn128Point2{result}
}

func (g2Point *altbn128Point2) Equals(otherPoint2 Point) bool {
	if other, ok := (otherPoint2).(*altbn128Point2); ok {
		return bytes.Equal(g2Point.point.Marshal(), other.point.Marshal())
	}
	return false
}

func (g2Point *altbn128Point2) Marshal() []byte {
	coords := g2Point.ToAffineCoords()
	xiBytes := pad32Bytes(coords[0].Bytes())
	xrBytes := pad32Bytes(coords[1].Bytes())
	y2 := &complexNum{coords[2], coords[3]}
	y2.Exp(y2, two, altbnG1Q)
	coords[2].Mul(coords[2], two)
	coords[3].Mul(coords[3], two)
	if coords[2].Cmp(altbnG1Q) == 1 {
		xiBytes[0] += 128
	}
	if coords[3].Cmp(altbnG1Q) == 1 {
		xrBytes[0] += 128
	}
	xBytes := make([]byte, 64, 64)
	copy(xBytes[:32], xiBytes)
	copy(xBytes[32:], xrBytes)
	return xBytes
}

func (g2Point *altbn128Point2) MarshalUncompressed() []byte {
	return g2Point.point.Marshal()
}

func (g2Point *altbn128Point2) Negate() *altbn128Point2 {
	coords := g2Point.ToAffineCoords()
	coords[2].Sub(altbnG1Q, coords[2])
	coords[3].Sub(altbnG1Q, coords[3])
	newPt, _ := Altbn128.MakeG2Point(coords, false)
	return newPt.(*altbn128Point2)
}

func (g2Point *altbn128Point2) Mul(scalar *big.Int) Point {
	scalar2 := new(big.Int)
	cmp := scalar.Cmp(zero)
	if cmp < 0 {
		g2Point = g2Point.Negate()
		scalar2.Mul(scalar, big.NewInt(-1))
	} else if cmp == 0 {
		return Altbn128.GetG2Infinity()
	} else {
		scalar2 = scalar
	}
	prod := new(bn256.G2).ScalarMult(g2Point.point, scalar2)
	ret := &altbn128Point2{prod}
	return ret
}

// ToAffineCoords returns the affine coordinate representation of the point
// in the form: [x0, x1, y0, y1], where X = x0 * u + x1, and Y = y0 * u + y1
func (g2Point *altbn128Point2) ToAffineCoords() []*big.Int {
	Bytestream := g2Point.point.Marshal()
	x0Bytes, x1Bytes := Bytestream[:32], Bytestream[32:64]
	y0Bytes, y1Bytes := Bytestream[64:96], Bytestream[96:128]
	x0 := new(big.Int).SetBytes(x0Bytes)
	x1 := new(big.Int).SetBytes(x1Bytes)
	y0 := new(big.Int).SetBytes(y0Bytes)
	y1 := new(big.Int).SetBytes(y1Bytes)
	return []*big.Int{x0, x1, y0, y1}
}

func (gTPoint altbn128PointT) Add(otherPointT PointT) (PointT, bool) {
	if other, ok := (otherPointT).(altbn128PointT); ok {
		sum := new(bn256.GT).Add(gTPoint.point, other.point)
		ret := altbn128PointT{sum}
		return ret, true
	}
	return nil, false
}

func (gTPoint altbn128PointT) Copy() PointT {
	result := new(bn256.GT)
	result.Unmarshal(gTPoint.point.Marshal())
	return &altbn128PointT{result}
}

func (gTPoint altbn128PointT) Marshal() []byte {
	return gTPoint.point.Marshal()
}

func (gTPoint altbn128PointT) Equals(otherPointT PointT) bool {
	if other, ok := (otherPointT).(altbn128PointT); ok {
		return bytes.Equal(gTPoint.Marshal(), other.Marshal())
	}
	return false
}

func (gTPoint altbn128PointT) Mul(scalar *big.Int) PointT {
	prod := new(bn256.GT).ScalarMult(gTPoint.point, scalar)
	ret := altbn128PointT{prod}
	return ret
}

func (curve *altbn128) UnmarshalG1(data []byte) (Point, bool) {
	if data == nil || (len(data) != 64 && len(data) != 32) {
		return nil, false
	}
	if len(data) == 64 { // No point compression
		curvePoint := new(bn256.G1)
		if _, ok := curvePoint.Unmarshal(data); ok == nil {
			return &altbn128Point1{curvePoint}, true
		}
	} else if len(data) == 32 { // Point compression
		ySgn := (data[0] >= 128)
		if ySgn {
			data[0] -= 128
		}
		x := new(big.Int).SetBytes(data)
		if x.Cmp(zero) == 0 {
			return Altbn128.GetG1Infinity(), true
		}
		y := Altbn128.g1XToYSquared(x)
		// Underlying library already checks that y is on the curve, thus isQuadRes isn't checked here
		y = calcQuadRes(y, altbnG1Q)
		doubleY := new(big.Int).Mul(y, two)
		// TODO switch this to use the parity method
		cmpRes := doubleY.Cmp(altbnG1Q)
		if ySgn && cmpRes == -1 {
			y.Sub(altbnG1Q, y)
		} else if !ySgn && cmpRes == 1 {
			y.Sub(altbnG1Q, y)
		}
		return Altbn128.MakeG1Point([]*big.Int{x, y}, true)
	}
	return nil, false
}

func (curve *altbn128) UnmarshalG2(data []byte) (Point, bool) {
	if data == nil || (len(data) != 64 && len(data) != 128) {
		return nil, false
	}
	if len(data) == 128 { // No point compression
		curvePoint := new(bn256.G2)
		if _, ok := curvePoint.Unmarshal(data); ok == nil {
			return &altbn128Point2{curvePoint}, true
		}
	} else if len(data) == 64 { // Point compression
		xiBytes := data[:32]
		xrBytes := data[32:]
		yiSgn := (xiBytes[0] >= 128)
		yrSgn := (xrBytes[0] >= 128)
		if yiSgn {
			xiBytes[0] -= 128
		}
		if yrSgn {
			xrBytes[0] -= 128
		}
		xi := new(big.Int).SetBytes(xiBytes)
		xr := new(big.Int).SetBytes(xrBytes)
		if xi.Cmp(zero) == 0 && xr.Cmp(zero) == 0 {
			return Altbn128.MakeG2Point([]*big.Int{zero, zero, zero, zero}, false)
		}
		x := &complexNum{xi, xr}
		y := Altbn128.g2XToYSquared(x)
		// Underlying library already checks that y is on the curve, thus isQuadRes isn't checked here
		y = calcComplexQuadRes(y, altbnG1Q)
		doubleYRe := new(big.Int).Mul(y.re, two)
		doubleYIm := new(big.Int).Mul(y.im, two)
		cmpResRe := doubleYRe.Cmp(altbnG1Q)
		cmpResIm := doubleYIm.Cmp(altbnG1Q)
		if yiSgn && cmpResIm == -1 {
			y.im.Sub(altbnG1Q, y.im)
		} else if !yiSgn && cmpResIm == 1 {
			y.im.Sub(altbnG1Q, y.im)
		}
		if yrSgn && cmpResRe == -1 {
			y.re.Sub(altbnG1Q, y.re)
		} else if !yrSgn && cmpResRe == 1 {
			y.re.Sub(altbnG1Q, y.re)
		}
		return Altbn128.MakeG2Point([]*big.Int{x.im, x.re, y.im, y.re}, false)
	}
	return nil, false
}

func (curve *altbn128) UnmarshalGT(data []byte) (PointT, bool) {
	if data == nil || len(data) != 384 {
		return nil, false
	}
	curvePoint := new(bn256.GT)
	if _, ok := curvePoint.Unmarshal(data); ok == nil {
		return altbn128PointT{curvePoint}, true
	}
	return nil, false
}

func (curve *altbn128) getG1A() *big.Int {
	return zero
}

func (curve *altbn128) getG1B() *big.Int {
	return altbnG1B
}

func (curve *altbn128) GetG1Q() *big.Int {
	return altbnG1Q
}

func (curve *altbn128) getG1QDivTwo() *big.Int {
	return altbnG1QDiv2
}

func (curve *altbn128) GetG1Order() *big.Int {
	return altbnG1Order
}

func (curve *altbn128) g1XToYSquared(x *big.Int) *big.Int {
	result := new(big.Int)
	result.Exp(x, three, altbnG1Q)
	result.Add(result, altbnG1B)
	return result
}

func (curve *altbn128) g2XToYSquared(x *complexNum) *complexNum {
	result := getComplexZero()
	result.Exp(x, three, altbnG1Q)
	result.Add(result, altbnG2B, altbnG1Q)
	return result
}

func (curve *altbn128) GetG1() Point {
	return altbnG1
}

func (curve *altbn128) GetG2() Point {
	return altbnG2
}

func (curve *altbn128) GetG1Infinity() (pt Point) {
	pt, _ = curve.MakeG1Point([]*big.Int{zero, zero}, false)
	return
}

func (curve *altbn128) GetG2Infinity() Point {
	pt, _ := curve.MakeG2Point([]*big.Int{zero, zero, zero, zero}, false)
	return pt
}

func (curve *altbn128) GetGTIdentity() PointT {
	return altbnGTIdentity
}

func (curve *altbn128) GetGT() PointT {
	return altbnGT
}

func (curve *altbn128) getG1Cofactor() *big.Int {
	return one
}

func (curve *altbn128) getFTHashParams() (*big.Int, *big.Int) {
	return altbnSqrtn3, altbnZ
}

//curve specific constants
var altbnG1B = big.NewInt(3)
var altbnG1Q, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
var altbnG1QDiv2 = new(big.Int).Div(altbnG1Q, two)

var altbnG2BRe, _ = new(big.Int).SetString("19485874751759354771024239261021720505790618469301721065564631296452457478373", 10)
var altbnG2BIm, _ = new(big.Int).SetString("266929791119991161246907387137283842545076965332900288569378510910307636690", 10)
var altbnG2B = &complexNum{altbnG2BIm, altbnG2BRe}

//precomputed Z = (-1 + sqrt(-3))/2 in Fq
var altbnZ, _ = new(big.Int).SetString("2203960485148121921418603742825762020974279258880205651966", 10)

//precomputed sqrt(-3) in Fq
var altbnSqrtn3, _ = new(big.Int).SetString("4407920970296243842837207485651524041948558517760411303933", 10)

var altbnG1 = &altbn128Point1{new(bn256.G1).ScalarBaseMult(one)}
var altbnG2 = &altbn128Point2{new(bn256.G2).ScalarBaseMult(one)}
var altbnGT, _ = Altbn128.Pair(altbnG1, altbnG2)

// Ensure zero has been created
var z = zero
var altbnGTIdentity, _ = Altbn128.Pair(Altbn128.GetG1(), Altbn128.GetG2Infinity())

var altbnG1Order, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Note that the cofactor in this curve is just 1

// AltbnSha3 Hashes a message to a point on Altbn128 using SHA3 and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnSha3(message []byte) []*big.Int {
	p1, p2 := tryAndIncrement64(message, sha3.Sum512, Altbn128)
	return []*big.Int{p1, p2}
}

// AltbnKeccak3 Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// Keccak3 is only for compatability with Ethereum hashing.
// The return value is the x,y affine coordinate pair.
func AltbnKeccak3(message []byte) []*big.Int {
	p1, p2 := tryAndIncrementEvm(message, EthereumSum256, Altbn128)
	return []*big.Int{p1, p2}
}

// AltbnBlake2b Hashes a message to a point on Altbn128 using Blake2b and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnBlake2b(message []byte) []*big.Int {
	p1, p2 := tryAndIncrement64(message, blake2b.Sum512, Altbn128)
	return []*big.Int{p1, p2}
}

// HashToG1 Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// This is for compatability with Ethereum hashing.
// The return value is the altbn_128 library's internel representation for points.
func (curve *altbn128) HashToG1(message []byte) Point {
	coords := AltbnKeccak3(message)
	p, _ := curve.MakeG1Point(coords, false)
	return p
}

// EthereumSum256 returns the Keccak3-256 digest of the data. This is because Ethereum
// uses a non-standard hashing algo.
func EthereumSum256(data []byte) (digest [32]byte) {
	h := gosha3.NewKeccak256()
	h.Write(data)
	h.Sum(digest[:0])
	return
}
