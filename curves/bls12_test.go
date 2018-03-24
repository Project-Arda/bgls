// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestG1BlindingMatches(t *testing.T) {
	N := 100
	msgSize := 64
	for i := 0; i < N; i++ {
		msg := make([]byte, msgSize)
		_, _ = rand.Read(msg)

		p1 := Bls12.HashToG1(msg)
		p2 := Bls12.HashToG1Blind(msg)
		assert.True(t, p1.Equals(p2), "inconsistent results with BLS normal and blind hashing to G1")
	}
}

func TestG1SwEncodeDegenerate(test *testing.T) {
	infty, _ := Bls12.MakeG1Point(zero, zero, false)
	var zeroArr [64]byte
	chkInfty := bls12FouqueTibouchi(zeroArr, false)
	assert.True(test, chkInfty.Equals(infty), "Degenerate case for t=0 did not return the point at infinity.")

	g1 := Bls12.GetG1()
	negG1 := g1.(*bls12Point1).Negate()
	t := new(big.Int).Sub(bls12Q, big.NewInt(5))
	t = calcQuadRes(t, bls12Q)
	var tArr [64]byte
	tBytes := t.Bytes()
	copy(tArr[64-len(tBytes):], tBytes)
	chkNegG1 := bls12FouqueTibouchi(tArr, false)
	_, y := chkNegG1.ToAffineCoords()
	assert.True(test, parity(y, bls12Q) == parity(t, bls12Q), "Parity for t=sqrt(-5) doesn't match return value")
	assert.True(test, chkNegG1.Equals(negG1), "Degenerate case for t=sqrt(-5) did not return g1.")
	t.Sub(bls12Q, t)
	tBytes = t.Bytes()
	copy(tArr[64-len(tBytes):], tBytes)
	chkG1 := bls12FouqueTibouchi(tArr, false)
	_, y = chkG1.ToAffineCoords()
	assert.True(test, parity(y, bls12Q) == parity(t, bls12Q), "Parity for t=-sqrt(-5) doesn't match return value")
	assert.True(test, chkG1.Equals(g1), "Degenerate case for t=-sqrt(-5) did not return g1.")
	chkInfty, _ = g1.Add(negG1)
	assert.True(test, chkInfty.Equals(infty), "Point at infinity isn't being returned under addition")
}
