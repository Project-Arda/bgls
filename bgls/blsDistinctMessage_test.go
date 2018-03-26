// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"testing"

	. "github.com/Project-Arda/bgls/curves"
	"github.com/stretchr/testify/assert"
)

func TestDistinctMsgSingleSigner(t *testing.T) {
	for _, curve := range curves {
		sk, vk, err := KeyGen(curve)
		assert.Nil(t, err, "Key generation failed")
		d := make([]byte, 64)
		_, err = rand.Read(d)
		assert.Nil(t, err, "test data generation failed")
		sig := SignDistinctMsg(curve, sk, d)
		assert.True(t, VerifyDistinctMsg(curve, vk, d, sig), "Point1 verification failed")

		sigTmp := sig.Copy()
		sigTmp, _ = sigTmp.Add(curve.GetG1())
		sig2 := sigTmp
		assert.False(t, VerifyDistinctMsg(curve, vk, d, sig2), "Point1 verification succeeding when it shouldn't")
	}
}

func TestDistinctMsgAggregation(t *testing.T) {
	for _, curve := range curves {
		N, Size := 6, 32
		msgs := make([][]byte, N+1)
		sigs := make([]Point1, N+1)
		pubkeys := make([]Point2, N+1)
		for i := 0; i < N; i++ {
			msgs[i] = make([]byte, Size)
			rand.Read(msgs[i])

			sk, vk, _ := KeyGen(curve)
			sig := SignDistinctMsg(curve, sk, msgs[i])
			pubkeys[i] = vk
			sigs[i] = sig
		}
		aggSig := AggregateG1(sigs[:N])
		assert.True(t, VerifyAggregateDistinctMsg(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 verification failed")
		assert.False(t, VerifyAggregateDistinctMsg(curve, aggSig, pubkeys[:N-1], msgs[:N]),
			"Aggregate Point1 verification succeeding without enough pubkeys")
		skf, vkf, _ := KeyGen(curve)
		pubkeys[N] = vkf
		sigs[N] = Sign(curve, skf, msgs[0])
		msgs[N] = msgs[0]
		aggSig = AggregateG1(sigs)
		msgs[0] = msgs[1]
		msgs[1] = msgs[N]
		aggSig = AggregateG1(sigs[:N])
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 succeeded with messages 0 and 1 switched")

		// TODO Add tests to make sure there is no mutation
	}
}
