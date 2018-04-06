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

	// GTToAffineCoords(PointT) (*big.Int, *big.Int)

	UnmarshalG1([]byte) (Point, bool)
	UnmarshalG2([]byte) (Point, bool)
	UnmarshalGT([]byte) (PointT, bool)

	GetG1() Point
	GetG2() Point
	GetGT() PointT

	GetG1Infinity() Point
	GetG2Infinity() Point
	GetGTIdentity() PointT

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
	// Product of Pairings
	PairingProduct([]Point, []Point) (PointT, bool)
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

// AggregatePoints takes the sum of points.
func AggregatePoints(points []Point) Point {
	if len(points) == 2 { // No parallelization needed
		aggPoint, _ := points[0].Add(points[1])
		return aggPoint
	}
	// Aggregate all the points together using concurrency
	c := make(chan Point)

	// Initialize aggPoint to an array with elements being the sum of two
	// adjacent Points.
	counter := 0
	for i := 0; i < len(points); i += 2 {
		go concurrentAggregatePoints(i, points, c)
		counter++
	}
	aggPoint := make([]Point, counter)
	for i := 0; i < counter; i++ {
		aggPoint[i] = <-c
	}

	// Keep on aggregating every pair of points until only one aggregate point remains
	for {
		counter = 0
		if len(aggPoint) == 1 {
			break
		}
		for i := 0; i < len(aggPoint); i += 2 {
			go concurrentAggregatePoints(i, aggPoint, c)
			counter++
		}
		nxtAggPoint := make([]Point, counter)
		for i := 0; i < counter; i++ {
			nxtAggPoint[i] = <-c
		}
		aggPoint = nxtAggPoint
	}
	return aggPoint[0]
}

// concurrentAggregatePoints handles the channel for concurrent Aggregation of points.
// It only adds the element at points[start] and points[start + 1], and sends it through the channel
func concurrentAggregatePoints(start int, points []Point, c chan Point) {
	if start+1 >= len(points) {
		c <- points[start]
		return
	}
	summed, _ := points[start].Add(points[start+1])
	c <- summed
}

// concurrentPairingProduct computes a set of pairings in parallel,
// and then takes their product again using concurrency.
func concurrentPairingProduct(curve CurveSystem, points1 []Point, points2 []Point) (PointT, bool) {
	if len(points1) != len(points2) {
		return nil, false
	}
	// Compute all the pairings in parallel
	c := make(chan PointT)
	pairedPoints := make([]PointT, len(points1))
	for i := 0; i < len(pairedPoints); i++ {
		go concurrentPair(curve, points1[i], points2[i], c)
	}
	for i := 0; i < len(pairedPoints); i++ {
		pairedPoints[i] = <-c
		if pairedPoints[i] == nil {
			return nil, false
		}
	}
	counter := 0
	// Set aggPairedPoints to an array with elements being the sum of two
	// adjacent Points.
	for i := 0; i < len(pairedPoints); i += 2 {
		go concurrentAggregatePointTs(i, pairedPoints, c)
		counter++
	}
	aggPairedPoints := make([]PointT, counter)
	for i := 0; i < counter; i++ {
		aggPairedPoints[i] = <-c
	}

	// Keep on aggregating every pair of points until only one aggregate point remains
	for {
		counter = 0
		if len(aggPairedPoints) == 1 {
			break
		}
		for i := 0; i < len(aggPairedPoints); i += 2 {
			go concurrentAggregatePointTs(i, aggPairedPoints, c)
			counter++
		}
		nxtPairedPoints := make([]PointT, counter)
		for i := 0; i < counter; i++ {
			nxtPairedPoints[i] = <-c
		}
		aggPairedPoints = nxtPairedPoints
	}
	return aggPairedPoints[0], true
}

// concurrentAggregatePoints handles the channel for concurrent Aggregation of points.
// It only adds the element at points[start] and points[start + 1], and sends it through the channel
func concurrentAggregatePointTs(start int, points []PointT, c chan PointT) {
	if start+1 >= len(points) {
		c <- points[start]
		return
	}
	summed, _ := points[start].Add(points[start+1])
	c <- summed
}

type indexedPoint struct {
	index int
	pt    Point
}

// ScalePoints takes a set of points, and a set of multiples, and returns a
// new set of points multiplied by the corresponding factor.
func ScalePoints(pts []Point, factors []*big.Int) (newKeys []Point) {
	if factors == nil {
		return pts
	} else if len(pts) != len(factors) {
		return nil
	}
	newKeys = make([]Point, len(pts))
	c := make(chan *indexedPoint)
	for i := 0; i < len(pts); i++ {
		go concurrentScale(pts[i], factors[i], i, c)
	}
	for i := 0; i < len(pts); i++ {
		pt := <-c
		newKeys[pt.index] = pt.pt
	}
	return newKeys
}

func concurrentScale(key Point, factor *big.Int, index int, c chan *indexedPoint) {
	if factor == nil {
		c <- &indexedPoint{index, key.Copy()}
	} else {
		c <- &indexedPoint{index, key.Mul(factor)}
	}
}

// concurrentPair pairs pt with key, and sends the result down the channel.
func concurrentPair(curve CurveSystem, pt1 Point, pt2 Point, c chan PointT) {
	if targetPoint, ok := curve.Pair(pt1, pt2); ok {
		c <- targetPoint
		return
	}
	c <- nil
}
