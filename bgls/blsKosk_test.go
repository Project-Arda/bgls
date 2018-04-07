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
		msg := make([]byte, 64)
		_, err = rand.Read(msg)
		assert.Nil(t, err, "test data generation failed")
		sig := KoskSign(curve, sk, msg)
		assert.True(t, KoskVerifySingleSignature(curve, sig, vk, msg), "Kosk signature verification failed")

		sig2 := sig.Copy()
		sig2, _ = sig2.Add(curve.GetG1())
		assert.False(t, KoskVerifySingleSignature(curve, sig2, vk, msg), "Kosk signature succeeding when it shouldn't")

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
			aggsig := AggregateSignatures(sigs)
			assert.True(t, KoskVerifyMultiSignature(curve, aggsig, signers, msg),
				"Aggregate MultiSig verification failed")
			msg2 := make([]byte, Size)
			rand.Read(msg2)
			assert.False(t, KoskVerifyMultiSignature(curve, aggsig, signers, msg2),
				"Aggregate MultiSig verification succeeded on incorrect msg")
			_, vkf, _ := KeyGen(curve)
			aggkey := AggregateKeys(signers)
			assert.True(t, KoskVerifySingleSignature(curve, aggsig, aggkey, msg),
				"Aggregate MultiSig verification failed with the aggkey pre-aggregated")
			signers[0] = vkf
			assert.False(t, KoskVerifyMultiSignature(curve, aggsig, signers, msg),
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

func TestKoskAggregation(t *testing.T) {
	for _, curve := range curves {
		N, Size := 6, 32
		msgs := make([][]byte, N+1)
		sigs := make([]Point, N+1)
		pubkeys := make([]Point, N+1)
		for i := 0; i < N; i++ {
			msgs[i] = make([]byte, Size)
			rand.Read(msgs[i])

			sk, vk, _ := KeyGen(curve)
			sig := KoskSign(curve, sk, msgs[i])
			pubkeys[i] = vk
			sigs[i] = sig
		}
		aggSig := AggregateSignatures(sigs[:N])
		assert.True(t, KoskVerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point verification failed")
		assert.False(t, KoskVerifyAggregateSignature(curve, aggSig, pubkeys[:N-1], msgs[:N]),
			"Aggregate Point verification succeeding without enough pubkeys")
		skf, vkf, _ := KeyGen(curve)
		pubkeys[N] = vkf
		sigs[N] = KoskSign(curve, skf, msgs[0])
		msgs[N] = msgs[0]
		aggSig = AggregateSignatures(sigs)
		assert.True(t, KoskVerifyAggregateSignature(curve, aggSig, pubkeys, msgs),
			"Aggregate Signature failing with duplicate messages")
		assert.False(t, KoskVerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point succeeding with invalid signature")
		msgs[0] = msgs[1]
		msgs[1] = msgs[N]
		aggSig = AggregateSignatures(sigs[:N])
		assert.False(t, KoskVerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 succeeded with messages 0 and 1 switched")

		// TODO Add tests to make sure there is no mutation
	}
}
