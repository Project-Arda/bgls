// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"
)

// CurveSystem is a set of parameters and functions for a pairing based cryptosystem
// It has everything necessary to support all bgls functionality which we use.
type CurveSystem interface {
	Pair(Point1, Point2) (PointT, bool)
	MakeG1Point(*big.Int, *big.Int) (Point1, bool)
	// MakeG2Point(*big.Int, *big.Int) (Point2, bool)
	// MakeGTPoint(*big.Int, *big.Int) (PointT, bool)

	CopyG1(Point1) Point1
	CopyG2(Point2) Point2
	CopyGT(PointT) PointT

	MarshalG1(Point1) []byte
	MarshalG2(Point2) []byte
	MarshalGT(PointT) []byte

	G1Add(Point1, Point1) (Point1, bool)
	G1Mul(*big.Int, Point1) (Point1, bool)
	G1Equals(Point1, Point1) bool
	GetG1() Point1
	HashToG1(message []byte) Point1

	getG1Q() *big.Int
	getG1A() *big.Int
	getG1B() *big.Int
	getG1Order() *big.Int
	g1XToYSquared(*big.Int) *big.Int

	G2Add(Point2, Point2) (Point2, bool)
	G2Mul(*big.Int, Point2) (Point2, bool)
	G2Equals(Point2, Point2) bool
	GetG2() Point2

	getG2Q() *big.Int
	// getG2A() *big.Int
	// getG2B() *big.Int

	GTAdd(PointT, PointT) (PointT, bool)
	GTMul(*big.Int, PointT) (PointT, bool)
	GTEquals(PointT, PointT) bool
	// getGTA() *big.Int
	// getGTQ() *big.Int
	// getGTB() *big.Int
}

// Point1 is a way to represent a point on G1, in the first elliptic curve.
type Point1 interface {
	g1ToAffineCoords() (*big.Int, *big.Int)
}

// Point2 is a way to represent a point on G2, in the first elliptic curve.
type Point2 interface {
	// g2ToAffineCoords() (*big.Int, *big.Int)
}

// PointT is a way to represent a point on GT, in the first elliptic curve.
type PointT interface {
	// gTToAffineCoords() (*big.Int, *big.Int)
}
