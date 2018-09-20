// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"
	"testing"

	. "github.com/Project-Arda/bgls/curves"
	"github.com/stretchr/testify/assert"
)

var curves = []CurveSystem{Altbn128, Bls12}
var benchmarkCurve = Bls12

func TestSignatureConsistency(t *testing.T) {
	for _, curve := range curves {
		for i := 0; i < 10; i++ {
			sk, pk := KeyGen(curve)
			msg := make([]byte, 64)
			_, err := rand.Read(msg)
			assert.Nil(t, err, "test data generation failed")
			m := new(big.Int).SetBytes(msg)
			m.Mod(m, curve.GetG1Order())
			sig := Sign(curve, sk, m)
			assert.True(t, Verify(curve, sig, pk, m), "Standard bbsig "+
				"signature verification failed")
			sig = SignHashed(curve, sk, msg)
			assert.True(t, VerifyHashed(curve, sig, pk, msg), "Standard bbsig "+
				"signature verification failed")
		}
	}
}

func BenchmarkKeygen(b *testing.B) {
	b.ResetTimer()
	curve := Altbn128
	for i := 0; i < b.N; i++ {
		KeyGen(curve)
	}
}

func BenchmarkAltBnHashToCurve(b *testing.B) {
	curve := Altbn128
	ms := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		ms[i] = make([]byte, 64)
		rand.Read(ms[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		curve.HashToG1(ms[i])
	}
}

// func BenchmarkSigning(b *testing.B) {
// 	curve := Altbn128
// 	sks := make([]*big.Int, b.N)
// 	ms := make([][]byte, b.N)
// 	for i := 0; i < b.N; i++ {
// 		ms[i] = make([]byte, 64)
// 		rand.Read(ms[i])
// 		sk, _, _ := KeyGen(curve)
// 		sks[i] = sk
// 	}
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_ = Sign(curve, sks[i], ms[i])
// 	}
// }
//
// func BenchmarkVerification(b *testing.B) {
// 	curve := Altbn128
// 	message := make([]byte, 64)
// 	rand.Read(message)
// 	sk, vk, _ := KeyGen(curve)
// 	sig := Sign(curve, sk, message)
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		if !VerifySingleSignature(curve, sig, vk, message) {
// 			b.Error("verification failed")
// 		}
// 	}
// }
