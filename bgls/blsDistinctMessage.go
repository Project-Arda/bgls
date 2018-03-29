// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"

	. "github.com/Project-Arda/bgls/curves"
)

// This implements the method of using Distinct Messages for aggregate signatures.
// This ensures that no two messages are used from separate pubkeys by prepending
// the public key before the message.

//Sign creates a signature on a message with a private key
func SignDistinctMsg(curve CurveSystem, sk *big.Int, m []byte) Point1 {
	return SignDistinctMsgCustHash(curve, sk, m, curve.HashToG1)
}

// SignCustHash creates a signature on a message with a private key, using
// a supplied function to hash to g1.
func SignDistinctMsgCustHash(curve CurveSystem, sk *big.Int, m []byte, hash func([]byte) Point1) Point1 {
	msg := append(LoadPublicKey(curve, sk).MarshalUncompressed(), m...)
	h := hash(msg)
	i := h.Mul(sk)
	return i
}

// VerifyDistinctMsg checks that a single 'Distinct Message' signature is valid
func VerifyDistinctMsg(curve CurveSystem, pubKey Point2, m []byte, sig Point1) bool {
	msg := append(pubKey.MarshalUncompressed(), m...)
	return VerifySingleSignature(curve, pubKey, msg, sig)
}

func VerifyAggregateDistinctMsg(curve CurveSystem, aggsig Point1, keys []Point2, msgs [][]byte) bool {
	if len(keys) != len(msgs) {
		return false
	}
	prependedMsgs := make([][]byte, len(msgs))
	for i := 0; i < len(msgs); i++ {
		prependedMsgs[i] = append(keys[i].MarshalUncompressed(), msgs[i]...)
	}
	// Use true for allow duplicates even though duplicates aren't allowed
	// This is because the prepending ensures that there are no duplicates,
	// So setting this to true skips that check.
	return verifyAggSig(curve, aggsig, keys, prependedMsgs, true)
}
