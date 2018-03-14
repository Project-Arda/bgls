// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"
)

// CurveSystem is a set of parameters and functions for a pairing based cryptosystem
// It has everything necessary to support all bgls functionality which we use.
type CurveSystem interface {
	MakeG1Point(*big.Int, *big.Int) (Point1, bool)
	// MakeG2Point(*big.Int, *big.Int, *big.Int, *big.Int) (Point2, bool)
	// MakeGTPoint(*big.Int, *big.Int) (PointT, bool)

	//
	// GTToAffineCoords(PointT) (*big.Int, *big.Int)

	UnmarshalG1([]byte) (Point1, bool)
	UnmarshalG2([]byte) (Point2, bool)
	UnmarshalGT([]byte) (PointT, bool)

	GetG1() Point1
	GetG2() Point2
	GetGT() PointT

	HashToG1(message []byte) Point1

	getG1Q() *big.Int
	// getGTQ() *big.Int

	getG1Cofactor() *big.Int

	getG1A() *big.Int
	getG1B() *big.Int
	getG1Order() *big.Int
	g1XToYSquared(*big.Int) *big.Int
}

// Point1 is a way to represent a point on G1, in the first elliptic curve.
type Point1 interface {
	Add(Point1) (Point1, bool)
	Copy() Point1
	Equals(Point1) bool
	Marshal() []byte
	Mul(*big.Int) Point1
	Pair(Point2) (PointT, bool)
	ToAffineCoords() (*big.Int, *big.Int)
}

// Point2 is a way to represent a point on G2, in the first elliptic curve.
type Point2 interface {
	Add(Point2) (Point2, bool)
	Copy() Point2
	Equals(Point2) bool
	Marshal() []byte
	Mul(*big.Int) Point2
	ToAffineCoords() (*big.Int, *big.Int, *big.Int, *big.Int)
}

// PointT is a way to represent a point on GT, in the first elliptic curve.
type PointT interface {
	Add(PointT) (PointT, bool)
	Copy() PointT
	Equals(PointT) bool
	Marshal() []byte
	Mul(*big.Int) PointT
	// ToAffineCoords() (*big.Int, *big.Int)
}
