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

type altBn128 struct {
}

type altBn128Point1 struct {
	point *bn256.G1
}

type altBn128Point2 struct {
	point *bn256.G2
}

type altBn128PointT struct {
	point *bn256.GT
}

func (curve altBn128) g1ToAffineCoords(pt Point1) (x, y *big.Int) {
	p1, ok1 := (pt).(*altBn128Point1)
	if !ok1 {
		return nil, nil
	}
	Bytestream := p1.point.Marshal()
	xBytes, yBytes := Bytestream[:32], Bytestream[32:64]
	x = new(big.Int).SetBytes(xBytes)
	y = new(big.Int).SetBytes(yBytes)
	return
}

var Altbn128Inst = &altBn128{}

func (curve *altBn128) Pair(pt1 Point1, pt2 Point2) (PointT, bool) {
	p1, ok1 := (pt1).(*altBn128Point1)
	p2, ok2 := (pt2).(*altBn128Point2)
	if !ok1 || !ok2 {
		return nil, false
	}
	p3 := bn256.Pair(p1.point, p2.point)
	ret := altBn128PointT{p3}
	return ret, true
}

// AltbnMkG1Point copies points into []byte and unmarshals to get around curvePoint not being exported
// This is copied from bn256.G1.Marshal (modified)
func (curve *altBn128) MakeG1Point(x, y *big.Int) (Point1, bool) {
	xBytes, yBytes := x.Bytes(), y.Bytes()
	ret := make([]byte, 64)
	copy(ret[32-len(xBytes):], xBytes)
	copy(ret[64-len(yBytes):], yBytes)
	result, ok := new(bn256.G1).Unmarshal(ret)
	if !ok {
		return nil, false
	}
	return &altBn128Point1{result}, true
}

// AltbnG2ToCoord takes a point in G2 of Altbn_128, and returns its affine coordinates
func (curve *altBn128) MakeG2Point(pt *bn256.G2) (xx, xy, yx, yy *big.Int) {
	Bytestream := pt.Marshal()
	xxBytes, xyBytes, yxBytes, yyBytes := Bytestream[:32], Bytestream[32:64], Bytestream[64:96], Bytestream[96:128]
	xx = new(big.Int).SetBytes(xxBytes)
	xy = new(big.Int).SetBytes(xyBytes)
	yx = new(big.Int).SetBytes(yxBytes)
	yy = new(big.Int).SetBytes(yyBytes)
	return
}

func (curve *altBn128) CopyG1(a Point1) Point1 {
	a1, ok1 := (a).(*altBn128Point1)
	if !ok1 {
		return nil
	}
	p, _ := new(bn256.G1).Unmarshal(a1.point.Marshal())
	return &altBn128Point1{p}
}

func (curve *altBn128) CopyG2(a Point2) Point2 {
	a1, ok1 := (a).(*altBn128Point2)
	if !ok1 {
		return nil
	}
	p, _ := new(bn256.G2).Unmarshal(a1.point.Marshal())
	return &altBn128Point2{p}
}

func (curve *altBn128) CopyGT(a PointT) PointT {
	a1, ok1 := (a).(*altBn128PointT)
	if !ok1 {
		return nil
	}
	p, _ := new(bn256.GT).Unmarshal(a1.point.Marshal())
	return &altBn128PointT{p}
}

func (curve *altBn128) MarshalG1(a Point1) []byte {
	a1, ok1 := (a).(*altBn128Point1)
	if !ok1 {
		return nil
	}
	return a1.point.Marshal()
}

func (curve *altBn128) MarshalG2(a Point2) []byte {
	a1, ok1 := (a).(*altBn128Point2)
	if !ok1 {
		return nil
	}
	return a1.point.Marshal()
}

func (curve *altBn128) MarshalGT(a PointT) []byte {
	a1, ok1 := (a).(altBn128PointT)
	if !ok1 {
		return nil
	}
	return a1.point.Marshal()
}

func (curve *altBn128) G1Add(pt1 Point1, pt2 Point1) (Point1, bool) {
	p1, ok1 := (pt1).(*altBn128Point1)
	p2, ok2 := (pt2).(*altBn128Point1)
	if !ok1 || !ok2 {
		return nil, false
	}
	p3 := new(bn256.G1).Add(p1.point, p2.point)
	ret := &altBn128Point1{p3}
	return ret, true
}

func (curve *altBn128) G1Mul(scalar *big.Int, pt Point1) (Point1, bool) {
	p1, ok1 := (pt).(*altBn128Point1)
	if !ok1 {
		return nil, false
	}
	p3 := new(bn256.G1).ScalarMult(p1.point, scalar)
	ret := &altBn128Point1{p3}
	return ret, true
}

func (curve *altBn128) G1Equals(a, b Point1) bool {
	a1, ok1 := (a).(*altBn128Point1)
	b1, ok2 := (b).(*altBn128Point1)
	if !ok1 || !ok2 {
		return false
	}
	return bytes.Equal(a1.point.Marshal(), b1.point.Marshal())
}

func (curve *altBn128) getG1A() *big.Int {
	return zero
}

func (curve *altBn128) getG1B() *big.Int {
	return altbnG1B
}

func (curve *altBn128) getG1Q() *big.Int {
	return altbnG1Q
}

func (curve *altBn128) GetG1() Point1 {
	return altBnG1
}

func (curve *altBn128) getG1Order() *big.Int {
	return altbnG1Order
}

func (curve *altBn128) g1XToYSquared(x *big.Int) *big.Int {
	result := new(big.Int)
	result.Exp(x, three, altbnG1Q)
	result.Add(result, altbnG1B)
	return result
}

func (curve *altBn128) G2Add(pt1 Point2, pt2 Point2) (Point2, bool) {
	p1, ok1 := (pt1).(*altBn128Point2)
	p2, ok2 := (pt2).(*altBn128Point2)
	if !ok1 || !ok2 {
		return nil, false
	}
	p3 := new(bn256.G2).Add(p1.point, p2.point)
	ret := &altBn128Point2{p3}
	return ret, true
}

func (curve *altBn128) G2Mul(scalar *big.Int, pt Point2) (Point2, bool) {
	p1, ok1 := (pt).(*altBn128Point2)
	if !ok1 {
		return nil, false
	}
	p3 := new(bn256.G2).ScalarMult(p1.point, scalar)
	ret := &altBn128Point2{p3}
	return ret, true
}

func (curve *altBn128) G2Equals(a, b Point2) bool {
	a1, ok1 := (a).(*altBn128Point2)
	b1, ok2 := (b).(*altBn128Point2)
	if !ok1 || !ok2 {
		return false
	}
	return bytes.Equal(a1.point.Marshal(), b1.point.Marshal())
}

func (curve *altBn128) getG2Q() *big.Int {
	return altbnG2Q
}

func (curve *altBn128) GTAdd(pt1 PointT, pt2 PointT) (PointT, bool) {
	p1, ok1 := (pt1).(altBn128PointT)
	p2, ok2 := (pt2).(altBn128PointT)
	if !ok1 || !ok2 {
		return nil, false
	}
	p3 := new(bn256.GT).Add(p1.point, p2.point)
	ret := altBn128PointT{p3}
	return ret, true
}

func (curve *altBn128) GTEquals(a, b PointT) bool {
	a1, ok1 := a.(altBn128PointT)
	b1, ok2 := b.(altBn128PointT)
	if !ok1 || !ok2 {
		return false
	}
	return bytes.Equal(a1.point.Marshal(), b1.point.Marshal())
}

func (curve *altBn128) GTMul(scalar *big.Int, pt PointT) (PointT, bool) {
	p1, ok1 := (pt).(*altBn128Point2)
	if !ok1 {
		return nil, false
	}
	p3 := new(bn256.G2).ScalarMult(p1.point, scalar)
	ret := altBn128Point2{p3}
	return ret, true
}

func (curve *altBn128) GetG2() Point2 {
	return altBnG2
}

//curve specific constants
var altbnG1B = big.NewInt(3)
var altbnG1Q, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
var altbnG2Q = new(big.Int).Mul(altbnG1Q, altbnG1Q)

//precomputed Z = (-1 + sqrt(-3))/2 in Fq
var altbnZ, _ = new(big.Int).SetString("2203960485148121921418603742825762020974279258880205651966", 10)

//precomputed sqrt(-3) in Fq
var altbnSqrtn3, _ = new(big.Int).SetString("4407920970296243842837207485651524041948558517760411303933", 10)

var altBnG1 = &altBn128Point1{new(bn256.G1).ScalarBaseMult(one)}
var altBnG2 = &altBn128Point2{new(bn256.G2).ScalarBaseMult(one)}

var altbnG1Order, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Note that the cofactor in this curve is just 1

// AltbnSha3 Hashes a message to a point on Altbn128 using SHA3 and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnSha3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, sha3.Sum512, Altbn128Inst)
	return
}

// AltbnKeccak3 Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// Keccak3 is only for compatability with Ethereum hashing.
// The return value is the x,y affine coordinate pair.
func AltbnKeccak3(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash32(message, EthereumSum256, Altbn128Inst)
	return
}

// AltbnBlake2b Hashes a message to a point on Altbn128 using Blake2b and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnBlake2b(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, blake2b.Sum512, Altbn128Inst)
	return
}

// AltbnKang12 Hashes a message to a point on Altbn128 using Blake2b and try and increment
// The return value is the x,y affine coordinate pair.
func AltbnKang12(message []byte) (p1, p2 *big.Int) {
	p1, p2 = hash64(message, kang12_64, Altbn128Inst)
	return
}

// AltbnHashToCurve Hashes a message to a point on Altbn128 using Keccak3 and try and increment
// This is for compatability with Ethereum hashing.
// The return value is the altbn_128 library's internel representation for points.
func (curve *altBn128) HashToG1(message []byte) Point1 {
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
