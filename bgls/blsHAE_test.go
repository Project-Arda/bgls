// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"testing"

	. "github.com/Project-Arda/bgls/curves"
	"github.com/stretchr/testify/assert"
)

func TestAggregationWithHAE(t *testing.T) {
	for _, curve := range curves {
		N, Size := 5, 32
		msgs := make([][]byte, N+1)
		sigs := make([]Point, N+1)
		pubkeys := make([]Point, N+1)
		for i := 0; i < N; i++ {
			msgs[i] = make([]byte, Size)
			rand.Read(msgs[i])

			sk, vk, _ := KeyGen(curve)
			sig := Sign(curve, sk, msgs[i])
			pubkeys[i] = vk
			sigs[i] = sig
		}
		aggSig := AggregateSignaturesWithHAE(sigs[:N], pubkeys[:N])
		assert.True(t, VerifyAggregateSignatureWithHAE(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 verification failed")
		assert.False(t, VerifyAggregateSignatureWithHAE(curve, aggSig, pubkeys[:N-1], msgs[:N]),
			"Aggregate Point1 verification succeeding without enough pubkeys")
		assert.Nil(t, AggregateSignaturesWithHAE(sigs[:N], pubkeys[:N-1]),
			"Aggregation of signatures succeeding with differing numbers of signatures"+
				" and pubkeys")
		skf, vkf, _ := KeyGen(curve)
		pubkeys[N] = vkf
		msgs[N] = msgs[0]
		sigs[N] = Sign(curve, skf, msgs[N])
		aggSig = AggregateSignaturesWithHAE(sigs, pubkeys)
		assert.True(t, VerifyAggregateSignatureWithHAE(curve, aggSig, pubkeys, msgs),
			"Aggregate HAE signature failing with duplicate messages")
		assert.False(t, VerifyAggregateSignatureWithHAE(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 succeeding with invalid signature")
		msgs[0] = msgs[1]
		msgs[1] = msgs[N]
		aggSig = AggregatePoints(sigs[:N])
		assert.False(t, VerifyAggregateSignatureWithHAE(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 succeeded with messages 0 and 1 switched")

		// TODO Add tests to make sure there is no mutation
	}
}

func TestMultiSigWithHAE(t *testing.T) {
	for _, curve := range curves {
		Tests, Size, Signers := 5, 32, 8
		for i := 0; i < Tests; i++ {
			msg := make([]byte, Size)
			rand.Read(msg)
			signers := make([]Point, Signers)
			sigs := make([]Point, Signers)
			for j := 0; j < Signers; j++ {
				sk, vk, _ := KeyGen(curve)
				sigs[j] = Sign(curve, sk, msg)
				signers[j] = vk
			}
			aggSig := AggregateSignaturesWithHAE(sigs, signers)
			assert.True(t, VerifyMultiSignatureWithHAE(curve, aggSig, signers, msg),
				"Aggregate MultiSig verification failed")
			msg2 := make([]byte, Size)
			rand.Read(msg2)
			assert.False(t, VerifyMultiSignatureWithHAE(curve, aggSig, signers, msg2),
				"Aggregate MultiSig verification succeeded on incorrect msg")
			_, vkf, _ := KeyGen(curve)
			signers[0] = vkf
			assert.False(t, VerifyMultiSignatureWithHAE(curve, aggSig, signers, msg),
				"Aggregate MultiSig verification succeeded on incorrect signers")
		}
	}
}
