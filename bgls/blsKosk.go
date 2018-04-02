// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"math/big"

	. "github.com/Project-Arda/bgls/curves"
)

// Knowledge of secret key bls. This is normal bls, however you do a zero
// knowledge proof to show that you know the secret key, which is done in the
// authentication methods here.

// Signing and verification proceeds as normal bgls, as long as all the public keys
// are known to have been authenticated.

// Authenticate generates an Authentication for a valid *big.Int/Point2 combo
// It signs a verification key with x.
func Authenticate(curve CurveSystem, sk *big.Int) Point {
	return AuthenticateCustHash(curve, sk, curve.HashToG1)
}

// AuthenticateCustHash generates an Authentication for a valid *big.Int/Point2 combo
// It signs a verification key with x. This runs with the specified hash function.
func AuthenticateCustHash(curve CurveSystem, sk *big.Int, hash func([]byte) Point) Point {
	m := LoadPublicKey(curve, sk).Marshal()
	return SignCustHash(sk, m, hash)
}

//CheckAuthentication verifies that this Point2 is valid
func CheckAuthentication(curve CurveSystem, v Point, authentication Point) bool {
	return CheckAuthenticationCustHash(curve, v, authentication, curve.HashToG1)
}

//CheckAuthenticationCustHash verifies that this Point2 is valid, with the specified hash function
func CheckAuthenticationCustHash(curve CurveSystem, v Point, authentication Point, hash func([]byte) Point) bool {
	m := v.Marshal()
	return VerifySingleSignatureCustHash(curve, v, m, authentication, hash)
}

// VerifyAggregateKoskSignature verifies that the aggregated signature proves that all messages were signed by associated keys
// Will fail under duplicate messages, unless allow duplicates is True.
func VerifyAggregateKoskSignature(curve CurveSystem, aggsig Point, keys []Point, msgs [][]byte) bool {
	return verifyAggSig(curve, aggsig, keys, msgs, true)
}

//Verify checks that a single message has been signed by a set of keys
//vulnerable against rogue public-key attack, if keys have not been authenticated
func (m MultiSig) Verify(curve CurveSystem) bool {
	return VerifyMultiSignature(curve, m.sig, m.keys, m.msg)
}

// VerifyMultiSignature checks that the aggregate signature correctly proves that a single message has been signed by a set of keys,
// vulnerable against chosen key attack, if keys have not been authenticated
func VerifyMultiSignature(curve CurveSystem, aggsig Point, keys []Point, msg []byte) bool {
	vs := AggregatePoints(keys)
	return VerifySingleSignature(curve, vs, msg, aggsig)
}

// VerifyMultiSignatureWithMultiplicity verifies a BLS multi signature where multiple copies of each signature may have been included in the aggregation
func VerifyMultiSignatureWithMultiplicity(curve CurveSystem, aggsig Point, keys []Point, multiplicity []int64, msg []byte) bool {
	if multiplicity == nil {
		return VerifyMultiSignature(curve, aggsig, keys, msg)
	} else if len(keys) != len(multiplicity) {
		return false
	}
	factors := make([]*big.Int, len(multiplicity))
	for i := 0; i < len(keys); i++ {
		factors[i] = big.NewInt(multiplicity[i])
	}
	scaledKeys := ScalePoints(keys, factors)
	return VerifyMultiSignature(curve, aggsig, scaledKeys, msg)
}
