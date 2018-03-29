// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"

	"golang.org/x/crypto/blake2b"

	. "github.com/Project-Arda/bgls/curves"
)

// BLS with hashed aggregation exponents(HAE). This is normal bls, but when aggregating
// you hash the `n` public keys to get `n` numbers in the range [0,2^(128)).
// Call these numbers t_0, t_1, ... t_{n-1}. Then you scale the ith signature to the
// by t_i, before multiplying them together.

// For Verification, you rehash to get t_0, t_1, ... t_{n-1}, and scale the public keys
// by this. Then BLS proceeds as normal with these scaled public keys.

// Note. I am calling this Hashed Aggregation Exponents in lieu of a better name
// for this defense against the rogue public key attack. This method is discussed
// with a corresponding security proof here:
// https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html#mjx-eqn-eqforge1

// AggregateSignaturesWithHAE aggregates the signatures, using the
// hashed exponents derived from the pubkeys to protect against the rogue
// public key attack.
func AggregateSignaturesWithHAE(sigs []Point, pubkeys []Point) Point {
	if len(pubkeys) != len(sigs) {
		return nil
	}
	t := hashPubKeysToExponents(pubkeys)
	newsigs := scalePoints(sigs, t)
	return AggregatePoints(newsigs)
}

// VerifyAggregateSignatureWithHAE verifies signatures of different messages aggregated with HAE.
func VerifyAggregateSignatureWithHAE(curve CurveSystem, aggsig Point, pubkeys []Point, msgs [][]byte) bool {
	t := hashPubKeysToExponents(pubkeys)
	newkeys := scalePoints(pubkeys, t)
	return verifyAggSig(curve, aggsig, newkeys, msgs, true)
}

// VerifyMultiSignatureWithHAE verifies signatures of the same message aggregated with HAE.
func VerifyMultiSignatureWithHAE(curve CurveSystem, aggsig Point, pubkeys []Point, msg []byte) bool {
	t := hashPubKeysToExponents(pubkeys)
	newkeys := scalePoints(pubkeys, t)
	return VerifyMultiSignature(curve, aggsig, newkeys, msg)
}

// My hash from G^n \to \R^n is using blake2x. The inputs to the hash are the
// uncompressed marshal's of each of the pubkeys.
func hashPubKeysToExponents(pubkeys []Point) []*big.Int {
	hashFunc, _ := blake2b.NewXOF(uint32(16*len(pubkeys)), []byte{})
	for i := 0; i < len(pubkeys); i++ {
		hashFunc.Write(pubkeys[i].MarshalUncompressed())
	}
	t := make([]*big.Int, len(pubkeys))
	for i := 0; i < len(pubkeys); i++ {
		sum := make([]byte, 16)
		hashFunc.Read(sum)
		t[i] = new(big.Int).SetBytes(sum)
	}
	return t
}
