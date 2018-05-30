// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	. "github.com/Project-Arda/bgls/curves" // nolint: golint
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"testing"
)

func TestAmsConsistency(t *testing.T) {
	numKeys := 15
	numSigners := 8
	for _, curve := range curves {
		pubkeys := make([]Point, numKeys, numKeys)
		secretKeys := make([]*big.Int, numKeys, numKeys)
		for i := 0; i < numKeys; i++ {
			secretKeys[i], pubkeys[i], _ = KeyGen(curve)
		}
		mkShares := make([][]Point, numKeys, numKeys)
		exps := hashPubKeysToExponents(pubkeys)
		apk := AggregatePoints(ScalePoints(pubkeys, exps))
		for i := 0; i < numKeys; i++ {
			mkShares[i] = AmsCreateMembershipKeyShares(curve, secretKeys[i], i, pubkeys)
			// Test that using the more efficient algorithm yields the same result.
			assert.Equal(t, mkShares[i], AmsCreateMembershipKeySharesKnownExp(curve, secretKeys[i], apk, exps[i], numKeys))
		}
		mkShares = reorganizeMembershipKeyShares(mkShares)
		membershipKeys := make([]Point, numKeys, numKeys)
		for i := 0; i < numKeys; i++ {
			membershipKeys[i] = AmsAggregateMembershipKeyShares(curve, mkShares[i])
			amsH2 := getAmsH2(curve, apk)
			pt1, ok1 := curve.Pair(membershipKeys[i], curve.GetG2())
			pt2, ok2 := curve.Pair(amsH2([]byte(strconv.Itoa(i))), apk)
			assert.True(t, ok1)
			assert.True(t, ok2)
			assert.True(t, pt1.Equals(pt2))
		}

		// Now generate signatures. Generate a signature on 8 people. For simplicity,
		// use first 8 keys.
		signingKeys := pubkeys[:numSigners]
		signatureShares := make([]Point, numSigners, numSigners)
		set := make([]int, numSigners, numSigners)
		msg := make([]byte, 64)
		rand.Read(msg)
		for i := 0; i < numSigners; i++ {
			signatureShares[i] = AmsCreateSignatureShare(curve, secretKeys[i], membershipKeys[i], msg)
			set[i] = i
		}
		aggKey, aggSig := AmsCombineSignatureShares(signingKeys, signatureShares)
		assert.True(t, AmsVerifySignature(curve, apk, set, aggKey, aggSig, msg))
		assert.True(t, AmsVerifySignatureWithSetCheck(curve, func(set []int) bool { return len(set) > 5 },
			apk, set, aggKey, aggSig, msg))
	}
}

// Each of these rows is all the shares a given signer makes. This reorganizes it
// to be all of the shares a signer should receive. Basically transposes the matrix.
func reorganizeMembershipKeyShares(incomingMkShares [][]Point) [][]Point {
	trueMkSet := make([][]Point, len(incomingMkShares), len(incomingMkShares))
	for i := 0; i < len(incomingMkShares); i++ {
		trueMkSet[i] = make([]Point, len(incomingMkShares), len(incomingMkShares))
		for j := 0; j < len(incomingMkShares); j++ {
			trueMkSet[i][j] = incomingMkShares[j][i]
		}
	}
	return trueMkSet
}
