// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

var curves = []CurveSystem{Altbn128, Bls12}

func TestMarshal(t *testing.T) {
	for _, curve := range curves {
		numTests := 32
		requiredScalars := []*big.Int{big.NewInt(1), Altbn128.GetG1Order()}
		for i := 0; i < numTests; i++ {
			scalar, _ := rand.Int(rand.Reader, curve.GetG1Order())
			if i < len(requiredScalars) {
				scalar = requiredScalars[i]
			}

			mulg1 := curve.GetG1().Mul(scalar)
			marshalled := mulg1.Marshal()
			if recoveredG1, ok := curve.UnmarshalG1(marshalled); ok {
				assert.True(t, recoveredG1.Equals(mulg1),
					"Unmarshalling G1 is not consistent with Marshal G1")
			} else {
				t.Error("Unmarshalling G1 failed")
			}
			marshalled = marshalled[1:]
			if _, ok := curve.UnmarshalG1(marshalled); ok {
				t.Error("Unmarshalling G1 is succeeding when the byte array is of the wrong length")
			}

			mulg2 := curve.GetG2().Mul(scalar)
			marshalled = mulg2.Marshal()
			if recoveredG2, ok := curve.UnmarshalG2(marshalled); ok {
				assert.True(t, recoveredG2.Equals(mulg2),
					"Unmarshalling G2 is not consistent with Marshal G2")
			} else {
				t.Error("Unmarshalling G2 failed on scalar " + scalar.String())
			}
			marshalled = marshalled[1:]
			if _, ok := curve.UnmarshalG2(marshalled); ok {
				t.Error("Unmarshalling G2 is succeeding when the byte array is of the wrong length")
			}

			mulgT, _ := mulg1.Pair(curve.GetG2())
			marshalled = mulgT.Marshal()
			// fmt.Println("Coordinate wise representation of g1 * " + scalar.String() + " paired with g2")
			// for i := 0; i < 12; i++ { // Code to print coordinates
			// 	fmt.Println(marshalled[i*32 : (i+1)*32])
			// }
			if recoveredGT, ok := curve.UnmarshalGT(marshalled); ok {
				assert.True(t, recoveredGT.Equals(mulgT),
					"Unmarshalling GT is not consistent with Marshal GT")
			} else {
				t.Error("Unmarshalling GT failed")
			}
			marshalled = marshalled[1:]
			if _, ok := curve.UnmarshalGT(marshalled); ok {
				t.Error("Unmarshalling GT is succeeding when the byte array is of the wrong length")
			}
		}
	}
}
