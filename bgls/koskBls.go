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
func Authenticate(curve CurveSystem, sk *big.Int) Point1 {
	return AuthenticateCustHash(curve, sk, curve.HashToG1)
}

// AuthenticateCustHash generates an Authentication for a valid *big.Int/Point2 combo
// It signs a verification key with x. This runs with the specified hash function.
func AuthenticateCustHash(curve CurveSystem, sk *big.Int, hash func([]byte) Point1) Point1 {
	m := LoadPublicKey(curve, sk).Marshal()
	return SignCustHash(sk, m, hash)
}

//CheckAuthentication verifies that this Point2 is valid
func CheckAuthentication(curve CurveSystem, v Point2, authentication Point1) bool {
	return CheckAuthenticationCustHash(curve, v, authentication, curve.HashToG1)
}

//CheckAuthenticationCustHash verifies that this Point2 is valid, with the specified hash function
func CheckAuthenticationCustHash(curve CurveSystem, v Point2, authentication Point1, hash func([]byte) Point1) bool {
	m := v.Marshal()
	return VerifyCustHash(curve, v, m, authentication, hash)
}

// VerifyAggregateSignature verifies that the aggregated signature proves that all messages were signed by associated keys
// Will fail under duplicate messages, unless allow duplicates is True.
func VerifyAggregateKoskSignature(curve CurveSystem, aggsig Point1, keys []Point2, msgs [][]byte) bool {
	return verifyAggSig(curve, aggsig, keys, msgs, true)
}

//Verify checks that a single message has been signed by a set of keys
//vulnerable against rogue public-key attack, if keys have not been authenticated
func (m MultiSig) Verify(curve CurveSystem) bool {
	return VerifyMultiSignature(curve, m.sig, m.keys, m.msg)
}

// VerifyMultiSignature checks that the aggregate signature correctly proves that a single message has been signed by a set of keys,
// vulnerable against chosen key attack, if keys have not been authenticated
func VerifyMultiSignature(curve CurveSystem, aggsig Point1, keys []Point2, msg []byte) bool {
	vs := AggregateG2(keys)
	c := make(chan PointT)
	go concurrentPair(curve, aggsig, curve.GetG2(), c)
	go concurrentMsgPair(curve, msg, vs, c)
	e1 := <-c
	e2 := <-c
	return e1.Equals(e2)
}
