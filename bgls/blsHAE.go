// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

// BLS with hashed aggregation exponents(HAE). This is normal bls, but when aggregating
// you hash the `n` public keys to get `n` numbers in the range [0,2^(128)).
// Call these numbers t_0, t_1, ... t_{n-1}. Then you scale the ith signature to the
// by t_i, before multiplying them together.
//
// For Verification, you hash to obtain the same t_0, t_1, ... t_{n-1}, and scale
// the public keys accordingly. Then BLS proceeds as normal with these scaled public keys.
//
// The hash function from G^n \to \R^n is blake2x. The uncompressed marshal of every
// key is written to then blake2x instance. Then n 16 byte numbers are read from the XOF,
// each corresponding to a value of t.
//
// Note. I am calling this Hashed Aggregation Exponents in lieu of a better name
// for this defense against the rogue public key attack. This method is discussed
// with a corresponding security proof here:
// https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html#mjx-eqn-eqforge1
//
// If you are using HAE to secure against the rogue public key attack, you are
// intended to use: KeyGen, Sign, VerifySingleSignature, AggregateSignaturesWithHAE,
// VerifyMultiSignatureWithHAE, VerifyAggregateSignatureWithHAE

import (
	"crypto/rand"
	"math/big"

	"golang.org/x/crypto/blake2b"

	. "github.com/Project-Arda/bgls/curves" // nolint: golint
)

// AggregateSignaturesWithHAE aggregates the signatures, using the
// hashed exponents derived from the pubkeys to protect against the rogue
// public key attack.
func AggregateSignaturesWithHAE(sigs []Point, pubkeys []Point) Point {
	if len(pubkeys) != len(sigs) {
		return nil
	}
	t := hashPubKeysToExponents(pubkeys)
	newsigs := ScalePoints(sigs, t)
	return AggregatePoints(newsigs)
}

// VerifyAggregateSignatureWithHAE verifies signatures of different messages aggregated with HAE.
func VerifyAggregateSignatureWithHAE(curve CurveSystem, aggsig Point, pubkeys []Point, msgs [][]byte) bool {
	t := hashPubKeysToExponents(pubkeys)
	newkeys := ScalePoints(pubkeys, t)
	return verifyAggSig(curve, aggsig, newkeys, msgs, true)
}

// VerifyMultiSignatureWithHAE verifies signatures of the same message aggregated with HAE.
func VerifyMultiSignatureWithHAE(curve CurveSystem, aggsig Point, pubkeys []Point, msg []byte) bool {
	return VerifySingleSignature(curve, aggsig, getAggregatePubKey(curve, pubkeys), msg)
}

// VerifyBatchMultiSignatureWithHAE verifies multiple MultiSignatures
// are valid, in time faster than verifying each multisignature individually.
func VerifyBatchMultiSignatureWithHAE(curve CurveSystem, aggsigs []Point, aggpubkeys []Point, msgs [][]byte, allowDups bool) bool {
	if allowDups {
		t := make([]*big.Int, len(aggsigs), len(aggsigs))
		for i := 0; i < len(aggsigs); i++ {
			t[i], _ = rand.Int(rand.Reader, curve.GetG1Order())
		}
		ScalePoints(aggsigs, t)
	}
	aggsig := AggregateSignatures(aggsigs)
	return verifyAggSig(curve, aggsig, aggpubkeys, msgs, true)
}

func getAggregatePubKey(curve CurveSystem, pubkeys []Point) Point {
	t := hashPubKeysToExponents(pubkeys)
	return AggregatePoints(ScalePoints(pubkeys, t))
}

// This hash from G^n \to \R^n is using blake2x. The inputs to the hash are the
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
