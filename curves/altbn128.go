// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"bytes"
	"fmt"
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

// MakeG1Point copies points into []byte and unmarshals to get around curvePoint not being exported
// Note that check does nothing here, because the upstream library checks that the point is on the curve.
func (curve *altbn128) MakeG1Point(x, y *big.Int, check bool) (Point1, bool) {
	xBytes, yBytes := x.Bytes(), y.Bytes()
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

func (g1Point *altbn128Point1) Add(otherPoint1 Point1) (Point1, bool) {
	if other, ok := (otherPoint1).(*altbn128Point1); ok {
		sum := new(bn256.G1).Add(g1Point.point, other.point)
		ret := &altbn128Point1{sum}
		return ret, true
	}
	return nil, false
}

func (g1Point *altbn128Point1) Copy() Point1 {
	result := new(bn256.G1)
	result.Unmarshal(g1Point.point.Marshal())
	return &altbn128Point1{result}
}

func (g1Point *altbn128Point1) Equals(otherPoint1 Point1) bool {
	if other, ok := (otherPoint1).(*altbn128Point1); ok {
		return bytes.Equal(g1Point.point.Marshal(), other.point.Marshal())
	}
	return false
}

func (g1Point *altbn128Point1) Marshal() []byte {
	x, y := g1Point.ToAffineCoords()
	xBytes := pad32Bytes(x.Bytes())
	y.Mul(y, two)
	if y.Cmp(altbnG1Q) == 1 {
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

func (g1Point *altbn128Point1) Mul(scalar *big.Int) Point1 {
	prod := new(bn256.G1).ScalarMult(g1Point.point, scalar)
	ret := &altbn128Point1{prod}
	return ret
}

func (g1Point *altbn128Point1) Pair(g2Point Point2) (PointT, bool) {
	if other, ok := (g2Point).(*altbn128Point2); ok {
		p3 := bn256.Pair(g1Point.point, other.point)
		ret := altbn128PointT{p3}
		return ret, true
	}
	return nil, false
}

func (g1Point *altbn128Point1) ToAffineCoords() (x, y *big.Int) {
	Bytestream := g1Point.point.Marshal()
	xBytes, yBytes := Bytestream[:32], Bytestream[32:64]
	x = new(big.Int).SetBytes(xBytes)
	y = new(big.Int).SetBytes(yBytes)
	return
}

// MakeG2Point copies points into []byte and unmarshals to get around twistPoint not being exported
func (curve *altbn128) MakeG2Point(xx, xy, yx, yy *big.Int) (Point2, bool) {
	xxBytes, xyBytes := pad32Bytes(xx.Bytes()), pad32Bytes(xy.Bytes())
	yxBytes, yyBytes := pad32Bytes(yx.Bytes()), pad32Bytes(yy.Bytes())
	ret := make([]byte, 128)
	copy(ret[:32], xxBytes)
	copy(ret[32:], xyBytes)
	copy(ret[64:], yxBytes)
	copy(ret[96:], yyBytes)
	result := new(bn256.G2)
	var ok error
	_, ok = result.Unmarshal(ret)
	if ok != nil {
		fmt.Println(ok)
		fmt.Println(len(xxBytes), len(xyBytes), len(yxBytes), len(yyBytes))
		return nil, false
	}
	return &altbn128Point2{result}, true
}

func (g2Point *altbn128Point2) Add(otherPoint2 Point2) (Point2, bool) {
	if other, ok := (otherPoint2).(*altbn128Point2); ok {
		sum := new(bn256.G2).Add(g2Point.point, other.point)
		ret := &altbn128Point2{sum}
		return ret, true
	}
	return nil, false
}

func (g2Point *altbn128Point2) Copy() Point2 {
	result := new(bn256.G2)
	result.Unmarshal(g2Point.point.Marshal())
	return &altbn128Point2{result}
}

func (g2Point *altbn128Point2) Equals(otherPoint2 Point2) bool {
	if other, ok := (otherPoint2).(*altbn128Point2); ok {
		return bytes.Equal(g2Point.point.Marshal(), other.point.Marshal())
	}
	return false
}

func (g2Point *altbn128Point2) Marshal() []byte {
	xi, xr, yi, yr := g2Point.ToAffineCoords()
	xiBytes := pad32Bytes(xi.Bytes())
	xrBytes := pad32Bytes(xr.Bytes())
	y2 := &complexNum{yi, yr}
	y2.Exp(y2, two, altbnG1Q)
	yi.Mul(yi, two)
	yr.Mul(yr, two)
	if yi.Cmp(altbnG1Q) == 1 {
		xiBytes[0] += 128
	}
	if yr.Cmp(altbnG1Q) == 1 {
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

func (g2Point *altbn128Point2) Mul(scalar *big.Int) Point2 {
	prod := new(bn256.G2).ScalarMult(g2Point.point, scalar)
	ret := &altbn128Point2{prod}
	return ret
}

func (g2Point *altbn128Point2) ToAffineCoords() (xx, xy, yx, yy *big.Int) {
	Bytestream := g2Point.point.Marshal()
	xxBytes, xyBytes := Bytestream[:32], Bytestream[32:64]
	yxBytes, yyBytes := Bytestream[64:96], Bytestream[96:128]
	xx = new(big.Int).SetBytes(xxBytes)
	xy = new(big.Int).SetBytes(xyBytes)
	yx = new(big.Int).SetBytes(yxBytes)
	yy = new(big.Int).SetBytes(yyBytes)
	return
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

func (curve *altbn128) UnmarshalG1(data []byte) (Point1, bool) {
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
			return Altbn128.MakeG1Point(zero, zero, false)
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
		return Altbn128.MakeG1Point(x, y, true)
	}
	return nil, false
}

func (curve *altbn128) UnmarshalG2(data []byte) (Point2, bool) {
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
			return Altbn128.MakeG2Point(zero, zero, zero, zero)
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
		return Altbn128.MakeG2Point(x.im, x.re, y.im, y.re)
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

func (curve *altbn128) GetG1() Point1 {
	return altbnG1
}

func (curve *altbn128) GetG2() Point2 {
	return altbnG2
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
var altbnGT, _ = altbnG1.Pair(altbnG2)

var altbnG1Order, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Note that the cofactor in this curve is just 1

// AltbnSha3 Hashes a message to a point on Altbn128 using SHA3 and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnSha3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = tryAndIncrement64(message, sha3.Sum512, Altbn128)
	return
}

// AltbnKeccak3 Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// Keccak3 is only for compatability with Ethereum hashing.
// The return value is the x,y affine coordinate pair.
func AltbnKeccak3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = tryAndIncrementEvm(message, EthereumSum256, Altbn128)
	return
}

// AltbnBlake2b Hashes a message to a point on Altbn128 using Blake2b and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnBlake2b(message []byte) (p1, p2 *big.Int) {
	p1, p2 = tryAndIncrement64(message, blake2b.Sum512, Altbn128)
	return
}

// HashToG1 Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// This is for compatability with Ethereum hashing.
// The return value is the altbn_128 library's internel representation for points.
func (curve *altbn128) HashToG1(message []byte) Point1 {
	x, y := AltbnKeccak3(message)
	p, _ := curve.MakeG1Point(x, y, false)
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
