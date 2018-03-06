// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"bytes"
	"math/big"

	"github.com/dchest/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bn256"
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

func (curve *altbn128) Pair(pt1 Point1, pt2 Point2) (PointT, bool) {
	p1, ok1 := (pt1).(*altbn128Point1)
	p2, ok2 := (pt2).(*altbn128Point2)
	if !ok1 || !ok2 {
		return nil, false
	}
	p3 := bn256.Pair(p1.point, p2.point)
	ret := altbn128PointT{p3}
	return ret, true
}

// AltbnMkG1Point copies points into []byte and unmarshals to get around curvePoint not being exported
// This is copied from bn256.G1.Marshal (modified)
func (curve *altbn128) MakeG1Point(x, y *big.Int) (Point1, bool) {
	xBytes, yBytes := x.Bytes(), y.Bytes()
	ret := make([]byte, 64)
	copy(ret[32-len(xBytes):], xBytes)
	copy(ret[64-len(yBytes):], yBytes)
	result, ok := new(bn256.G1).Unmarshal(ret)
	if !ok {
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
	p, _ := new(bn256.G1).Unmarshal(g1Point.point.Marshal())
	return &altbn128Point1{p}
}

func (g1Point *altbn128Point1) Equals(otherPoint1 Point1) bool {
	if other, ok := (otherPoint1).(*altbn128Point1); ok {
		return bytes.Equal(g1Point.Marshal(), other.Marshal())
	}
	return false
}

func (g1Point *altbn128Point1) Marshal() []byte {
	return g1Point.point.Marshal()
}

func (g1Point *altbn128Point1) Mul(scalar *big.Int) Point1 {
	prod := new(bn256.G1).ScalarMult(g1Point.point, scalar)
	ret := &altbn128Point1{prod}
	return ret
}

func (g1Point *altbn128Point1) ToAffineCoords() (x, y *big.Int) {
	Bytestream := g1Point.Marshal()
	xBytes, yBytes := Bytestream[:32], Bytestream[32:64]
	x = new(big.Int).SetBytes(xBytes)
	y = new(big.Int).SetBytes(yBytes)
	return
}

// AltbnG2ToCoord takes a point in G2 of Altbn_128, and returns its affine coordinates
func (curve *altbn128) MakeG2Point(pt *bn256.G2) (xx, xy, yx, yy *big.Int) {
	Bytestream := pt.Marshal()
	xxBytes, xyBytes, yxBytes, yyBytes := Bytestream[:32], Bytestream[32:64], Bytestream[64:96], Bytestream[96:128]
	xx = new(big.Int).SetBytes(xxBytes)
	xy = new(big.Int).SetBytes(xyBytes)
	yx = new(big.Int).SetBytes(yxBytes)
	yy = new(big.Int).SetBytes(yyBytes)
	return
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
	p, _ := new(bn256.G2).Unmarshal(g2Point.point.Marshal())
	return &altbn128Point2{p}
}

func (g2Point *altbn128Point2) Equals(otherPoint2 Point2) bool {
	if other, ok := (otherPoint2).(*altbn128Point2); ok {
		return bytes.Equal(g2Point.Marshal(), other.Marshal())
	}
	return false
}

func (g2Point *altbn128Point2) Marshal() []byte {
	return g2Point.point.Marshal()
}

func (g2Point *altbn128Point2) Mul(scalar *big.Int) Point2 {
	prod := new(bn256.G2).ScalarMult(g2Point.point, scalar)
	ret := &altbn128Point2{prod}
	return ret
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
	p, _ := new(bn256.GT).Unmarshal(gTPoint.point.Marshal())
	return altbn128PointT{p}
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
	if data == nil || len(data) != 64 {
		return nil, false
	}
	if curvePoint, ok := new(bn256.G1).Unmarshal(data); ok {
		return &altbn128Point1{curvePoint}, true
	}
	return nil, false
}

func (curve *altbn128) UnmarshalG2(data []byte) (Point2, bool) {
	if data == nil || len(data) != 128 {
		return nil, false
	}
	if curvePoint, ok := new(bn256.G2).Unmarshal(data); ok {
		return &altbn128Point2{curvePoint}, true
	}
	return nil, false
}

func (curve *altbn128) UnmarshalGT(data []byte) (PointT, bool) {
	if data == nil || len(data) != 384 {
		return nil, false
	}
	if curvePoint, ok := new(bn256.GT).Unmarshal(data); ok {
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

func (curve *altbn128) getG1Q() *big.Int {
	return altbnG1Q
}

func (curve *altbn128) getG1Order() *big.Int {
	return altbnG1Order
}

func (curve *altbn128) g1XToYSquared(x *big.Int) *big.Int {
	result := new(big.Int)
	result.Exp(x, three, altbnG1Q)
	result.Add(result, altbnG1B)
	return result
}

func (curve *altbn128) getG2Q() *big.Int {
	return altbnG2Q
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

//curve specific constants
var altbnG1B = big.NewInt(3)
var altbnG1Q, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
var altbnG2Q = new(big.Int).Mul(altbnG1Q, altbnG1Q)

//precomputed Z = (-1 + sqrt(-3))/2 in Fq
var altbnZ, _ = new(big.Int).SetString("2203960485148121921418603742825762020974279258880205651966", 10)

//precomputed sqrt(-3) in Fq
var altbnSqrtn3, _ = new(big.Int).SetString("4407920970296243842837207485651524041948558517760411303933", 10)

var altbnG1 = &altbn128Point1{new(bn256.G1).ScalarBaseMult(one)}
var altbnG2 = &altbn128Point2{new(bn256.G2).ScalarBaseMult(one)}
var altbnGT, _ = Altbn128.Pair(altbnG1, altbnG2)

var altbnG1Order, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Note that the cofactor in this curve is just 1

// AltbnSha3 Hashes a message to a point on Altbn128 using SHA3 and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnSha3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, sha3.Sum512, Altbn128)
	return
}

// AltbnKeccak3 Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// Keccak3 is only for compatability with Ethereum hashing.
// The return value is the x,y affine coordinate pair.
func AltbnKeccak3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash32(message, EthereumSum256, Altbn128)
	return
}

// AltbnBlake2b Hashes a message to a point on Altbn128 using Blake2b and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnBlake2b(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, blake2b.Sum512, Altbn128)
	return
}

// AltbnKang12 Hashes a message to a point on Altbn128 using Blake2b and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnKang12(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, kang12_64, Altbn128)
	return
}

// AltbnHashToCurve Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// This is for compatability with Ethereum hashing.
// The return value is the altbn_128 library's internel representation for points.
func (curve *altbn128) HashToG1(message []byte) Point1 {
	x, y := AltbnKeccak3(message)
	p, _ := curve.MakeG1Point(x, y)
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
