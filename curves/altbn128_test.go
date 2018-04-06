// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEthereumHash(t *testing.T) {
	curve := Altbn128
	// Tests Altbn hash to curve against known solidity test case.
	a, _ := new(big.Int).SetString("9121282642809701931333593728297233225556711250127745709186816755779879923737", 10)
	aBytes := a.Bytes()
	coords := AltbnKeccak3(aBytes)
	expX, _ := new(big.Int).SetString("11423386531623885114587219621463106117140760157404497425836076043015227528156", 10)
	expY, _ := new(big.Int).SetString("20262289731964024720969923714809935701428881933342918937283877214228227624643", 10)
	assert.True(t, coords[0].Cmp(expX) == 0 && coords[1].Cmp(expY) == 0, "Hash does not match known Ethereum Output")
	pt := curve.HashToG1(aBytes)
	coords2 := pt.ToAffineCoords()
	assert.True(t, coords[0].Cmp(coords2[0]) == 0 && coords[1].Cmp(coords2[1]) == 0, "Conversion of point to coordinates is not working")

	coords = altbnG2.ToAffineCoords()
	knownxi, _ := new(big.Int).SetString("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10)
	knownxr, _ := new(big.Int).SetString("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10)
	knownyi, _ := new(big.Int).SetString("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10)
	knownyr, _ := new(big.Int).SetString("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10)

	assert.Zero(t, coords[0].Cmp(knownxi), "xi doesn't match")
	assert.Zero(t, coords[1].Cmp(knownxr), "xr doesn't match")
	assert.Zero(t, coords[2].Cmp(knownyi), "yi doesn't match")
	assert.Zero(t, coords[3].Cmp(knownyr), "yr doesn't match")

	altG2, _ := curve.MakeG2Point(coords, false)
	assert.True(t, altG2.Equals(curve.GetG2()), "MakeG2Point Failed")
}
