// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"math/big"
)

// CurveSystem is a set of parameters and functions for a pairing based cryptosystem
// It has everything necessary to support all bgls functionality which we use.
type CurveSystem interface {
	Name() string

	MakeG1Point([]*big.Int, bool) (Point, bool)
	MakeG2Point([]*big.Int, bool) (Point, bool)

	//
	// GTToAffineCoords(PointT) (*big.Int, *big.Int)

	UnmarshalG1([]byte) (Point, bool)
	UnmarshalG2([]byte) (Point, bool)
	UnmarshalGT([]byte) (PointT, bool)

	GetG1() Point
	GetG2() Point
	GetGT() PointT

	GetG1Infinity() Point
	GetG2Infinity() Point

	HashToG1(message []byte) Point

	GetG1Q() *big.Int
	GetG1Order() *big.Int
	// getGTQ() *big.Int

	getG1Cofactor() *big.Int

	getG1A() *big.Int
	getG1B() *big.Int
	// Fouque-Tibouchi hash parameters, sqrt(-3), (-1 + sqrt(-3))/2 computed in F_q
	getFTHashParams() (*big.Int, *big.Int)
	g1XToYSquared(*big.Int) *big.Int

	Pair(Point, Point) (PointT, bool)
}

// Point is a way to represent a point on G1 or G2, in the first two elliptic curves.
type Point interface {
	Add(Point) (Point, bool)
	Copy() Point
	Equals(Point) bool
	Marshal() []byte
	MarshalUncompressed() []byte
	Mul(*big.Int) Point
	ToAffineCoords() []*big.Int
}

// PointT is a way to represent a point on GT, in the target group
type PointT interface {
	Add(PointT) (PointT, bool)
	Copy() PointT
	Equals(PointT) bool
	Marshal() []byte
	Mul(*big.Int) PointT
	// ToAffineCoords() (*big.Int, *big.Int)
}
