// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

// This file implements the method of using Distinct Messages for aggregate signatures.
// This ensures that no two messages are used from separate pubkeys by prepending
// the public key before the message, thereby preventing the rogue public key
// attack.
//
// If you are using DistinctMsg to secure against the rogue public key attack, you are
// intended to use: AggregateSignatures, KeyGen, DistinctMsgSign,
// DistinctMsgVerifySingleSignature, DistinctMsgVerifyAggregateSignature

import (
	"math/big"

	. "github.com/Project-Arda/bgls/curves" // nolint: golint
)

// DistinctMsgSign creates a signature on a message with a private key, with
// prepending the public key to the message.
func DistinctMsgSign(curve CurveSystem, sk *big.Int, m []byte) Point {
	return DistinctMsgSignCustHash(curve, sk, m, curve.HashToG1)
}

// DistinctMsgSignCustHash creates a signature on a message with a private key, using
// a supplied function to hash to g1.
func DistinctMsgSignCustHash(curve CurveSystem, sk *big.Int, msg []byte, hash func([]byte) Point) Point {
	m := append(LoadPublicKey(curve, sk).MarshalUncompressed(), msg...)
	h := hash(m)
	i := h.Mul(sk)
	return i
}

// DistinctMsgVerifySingleSignature checks that a single 'Distinct Message' signature is valid
func DistinctMsgVerifySingleSignature(curve CurveSystem, pubkey Point, m []byte, sig Point) bool {
	msg := append(pubkey.MarshalUncompressed(), m...)
	return VerifySingleSignature(curve, pubkey, msg, sig)
}

// DistinctMsgVerifyAggregateSignature checks that an aggsig was generated from the
// the provided set of public key / msg pairs, when the messages are signed using
// the 'Distinct Message' method.
func DistinctMsgVerifyAggregateSignature(curve CurveSystem, aggsig Point, keys []Point, msgs [][]byte) bool {
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
