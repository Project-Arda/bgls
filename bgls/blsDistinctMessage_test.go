// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"testing"

	. "github.com/Project-Arda/bgls/curves" // nolint: golint
	"github.com/stretchr/testify/assert"
)

func TestDistinctMsgSingleSigner(t *testing.T) {
	for _, curve := range curves {
		sk, vk, err := KeyGen(curve)
		assert.Nil(t, err, "Key generation failed")
		d := make([]byte, 64)
		_, err = rand.Read(d)
		assert.Nil(t, err, "test data generation failed")
		sig := DistinctMsgSign(curve, sk, d)
		assert.True(t, DistinctMsgVerifySingleSignature(curve, vk, d, sig), "Point1 verification failed")

		sigTmp := sig.Copy()
		sigTmp, _ = sigTmp.Add(curve.GetG1())
		sig2 := sigTmp
		assert.False(t, DistinctMsgVerifySingleSignature(curve, vk, d, sig2), "Point1 verification succeeding when it shouldn't")
	}
}

func TestDistinctMsgAggregation(t *testing.T) {
	for _, curve := range curves {
		N, Size := 6, 32
		msgs := make([][]byte, N)
		sigs := make([]Point, N)
		pubkeys := make([]Point, N)
		for i := 0; i < N; i++ {
			msgs[i] = make([]byte, Size)
			rand.Read(msgs[i])

			sk, vk, _ := KeyGen(curve)
			sig := DistinctMsgSign(curve, sk, msgs[i])
			pubkeys[i] = vk
			sigs[i] = sig
		}
		aggSig := AggregatePoints(sigs)
		assert.True(t, DistinctMsgVerifyAggregateSignature(curve, aggSig, pubkeys, msgs),
			"Aggregate Point1 verification failed")
		assert.False(t, DistinctMsgVerifyAggregateSignature(curve, aggSig, pubkeys[:N-1], msgs),
			"Aggregate Point1 verification succeeding without enough pubkeys")
		msgs[0] = msgs[1]
		aggSig = AggregatePoints(sigs)
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys, msgs),
			"Aggregate Point1 succeeded with messages 0 and 1 switched")

		// TODO Add tests to make sure there is no mutation
	}
}
