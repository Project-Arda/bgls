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

// taken from https://github.com/ebfull/pairing/pull/30/commits/092a0f2846ca9e1a18eef849355e847f61eaf2bc
func TestKnownBls12G1Hashes(t *testing.T) {
	msg := []byte{}
	p := Bls12.HashToG1(msg)
	x, _ := new(big.Int).SetString("315124130825307604287835216317628428134609737854237653839182597515996444073032649481416725367158979153513345579672", 10)
	y, _ := new(big.Int).SetString("3093537746211397858160667262592024570071165158580434464756577567510401504168962073691924150397172185836012224315174", 10)
	q, ok := Bls12.MakeG1Point(x, y, true)
	if !ok {
		t.Error("known point not registering as on the curve")
	}
	assert.True(t, p.Equals(q))
}
