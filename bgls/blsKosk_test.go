// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"
	mathrand "math/rand"
	"testing"

	. "github.com/Project-Arda/bgls/curves"
	"github.com/stretchr/testify/assert"
)

func TestKoskSingleSigner(t *testing.T) {
	for _, curve := range curves {
		sk, vk, err := KeyGen(curve)
		assert.Nil(t, err, "Key generation failed")
		assert.True(t, CheckAuthentication(curve, vk, Authenticate(curve, sk)), "Key Authentication failed")
		d := make([]byte, 64)
		_, err = rand.Read(d)
		assert.Nil(t, err, "test data generation failed")
		sig := KoskSign(curve, sk, d)
		assert.True(t, KoskVerifySingleSignature(curve, vk, d, sig), "Point1 verification failed")

		sigTmp := sig.Copy()
		sigTmp, _ = sigTmp.Add(curve.GetG1())
		sig2 := sigTmp
		assert.False(t, KoskVerifySingleSignature(curve, vk, d, sig2), "Point1 verification succeeding when it shouldn't")

		// TODO Add tests to show that this doesn't succeed if d or vk is altered
	}
}

func TestKoskMultiSig(t *testing.T) {
	for _, curve := range curves {
		Tests, Size, Signers := 5, 32, 10
		for i := 0; i < Tests; i++ {
			msg := make([]byte, Size)
			rand.Read(msg)
			signers := make([]Point, Signers)
			sigs := make([]Point, Signers)
			for j := 0; j < Signers; j++ {
				sk, vk, _ := KeyGen(curve)
				sigs[j] = KoskSign(curve, sk, msg)
				signers[j] = vk
			}
			aggSig := AggregatePoints(sigs)
			assert.True(t, KoskVerifyMultiSignature(curve, aggSig, signers, msg),
				"Aggregate MultiSig verification failed")
			msg2 := make([]byte, Size)
			rand.Read(msg2)
			assert.False(t, KoskVerifyMultiSignature(curve, aggSig, signers, msg2),
				"Aggregate MultiSig verification succeeded on incorrect msg")
			_, vkf, _ := KeyGen(curve)
			signers[0] = vkf
			assert.False(t, KoskVerifyMultiSignature(curve, aggSig, signers, msg),
				"Aggregate MultiSig verification succeeded on incorrect signers")
		}
	}
}

func TestKoskMultiSigWithMultiplicity(t *testing.T) {
	for _, curve := range curves {
		Tests, Size, Signers := 5, 32, 10
		for i := 0; i < Tests; i++ {
			msg := make([]byte, Size)
			rand.Read(msg)
			signers := make([]Point, Signers)
			sigs := make([]Point, Signers)
			multi := make([]int64, Signers)
			for j := 0; j < Signers; j++ {
				sk, vk, _ := KeyGen(curve)
				multi[j] = mathrand.Int63()
				sigs[j] = KoskSign(curve, sk, msg).Mul(big.NewInt(multi[j]))
				signers[j] = vk
			}
			aggSig := AggregatePoints(sigs)
			assert.True(t, KoskVerifyMultiSignatureWithMultiplicity(curve, aggSig, signers, multi, msg),
				"Aggregate MultiSig verification failed")
			msg2 := make([]byte, Size)
			rand.Read(msg2)
			assert.False(t, KoskVerifyMultiSignatureWithMultiplicity(curve, aggSig, signers, multi, msg2),
				"Aggregate MultiSig verification succeeded on incorrect msg")
			_, vkf, _ := KeyGen(curve)
			signers[0] = vkf
			assert.False(t, KoskVerifyMultiSignatureWithMultiplicity(curve, aggSig, signers, multi, msg),
				"Aggregate MultiSig verification succeeded on incorrect signers")
		}
	}
}
