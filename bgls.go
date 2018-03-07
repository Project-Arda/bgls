// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"

	"math/big"
)

//MultiSig holds set of keys and one message plus signature
type MultiSig struct {
	keys []Point2
	sig  Point1
	msg  []byte
}

//AggSig holds paired sequences of keys and messages, and one signature
type AggSig struct {
	keys []Point2
	msgs [][]byte
	sig  Point1
}

//KeyGen generates a *big.Int and Point2
func KeyGen(curve CurveSystem) (*big.Int, Point2, error) {
	x, err := rand.Int(rand.Reader, curve.getG1Order())
	if err != nil {
		return nil, nil, err
	}
	pubKey := LoadPublicKey(curve, x)
	return x, pubKey, nil
}

//LoadKey turns secret key into SigninKey and Point2
func LoadPublicKey(curve CurveSystem, sk *big.Int) Point2 {
	pubKey := curve.GetG2().Mul(sk)
	return pubKey
}

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

//Sign creates a signature on a message with a private key
func Sign(curve CurveSystem, sk *big.Int, m []byte) Point1 {
	return SignCustHash(sk, m, curve.HashToG1)
}

// SignCustHash creates a signature on a message with a private key, using
// a supplied function to hash to g1.
func SignCustHash(sk *big.Int, m []byte, hash func([]byte) Point1) Point1 {
	h := hash(m)
	i := h.Mul(sk)
	return i
}

// Verify checks that a signature is valid
func Verify(curve CurveSystem, pubKey Point2, m []byte, sig Point1) bool {
	return VerifyCustHash(curve, pubKey, m, sig, curve.HashToG1)
}

// VerifyCustHash checks that a signature is valid with the supplied hash function
func VerifyCustHash(curve CurveSystem, pubKey Point2, m []byte, sig Point1, hash func([]byte) Point1) bool {
	h := hash(m)
	p1, ok1 := h.Pair(pubKey)
	p2, ok2 := sig.Pair(curve.GetG2())
	if !ok1 || !ok2 {
		return false
	}
	return p1.Equals(p2)
}

// AggregateG1 takes the sum of points on G1. This is used to convert a set of signatures into a single signature
func AggregateG1(sigs []Point1) Point1 {
	aggG1 := sigs[0].Copy()
	for _, s := range sigs[1:] {
		aggG1, _ = aggG1.Add(s)
	}
	return aggG1
}

// AggregateG2 takes the sum of points on G1. This is used to sum a set of public keys for the multisignature
func AggregateG2(keys []Point2) Point2 {
	aggG2 := keys[0].Copy()
	for _, s := range keys[1:] {
		aggG2, _ = aggG2.Add(s)
	}
	return aggG2
}

// Verify checks that all messages were signed by associated keys
// Will fail under duplicate messages
func (a AggSig) Verify(curve CurveSystem) bool {
	return VerifyAggregateSignature(curve, a.sig, a.keys, a.msgs, false)
}

// VerifyAggregateSignature verifies that the aggregated signature proves that all messages were signed by associated keys
// Will fail under duplicate messages, unless allow duplicates is True.
func VerifyAggregateSignature(curve CurveSystem, aggsig Point1, keys []Point2, msgs [][]byte, allowDuplicates bool) bool {
	if len(keys) != len(msgs) {
		return false
	}
	if !allowDuplicates {
		if containsDuplicateMessage(msgs) {
			return false
		}
	}
	e1, _ := aggsig.Pair(curve.GetG2())
	h := curve.HashToG1(msgs[0])
	e2, _ := h.Pair(keys[0])
	for i := 1; i < len(msgs); i++ {
		h = curve.HashToG1(msgs[i])
		e3, _ := h.Pair(keys[i]) // Temporary variable to store result of pairing
		e2, _ = e3.Add(e2)
	}
	return e1.Equals(e2)
}

//Verify checks that a single message has been signed by a set of keys
//vulnerable against chosen key attack, if keys have not been authenticated
func (m MultiSig) Verify(curve CurveSystem) bool {
	return VerifyMultiSignature(curve, m.sig, m.keys, m.msg)
}

// VerifyMultiSignature checks that the aggregate signature correctly proves that a single message has been signed by a set of keys,
// vulnerable against chosen key attack, if keys have not been authenticated
func VerifyMultiSignature(curve CurveSystem, aggsig Point1, keys []Point2, msg []byte) bool {
	e1, _ := aggsig.Pair(curve.GetG2())
	vs := AggregateG2(keys)
	h := curve.HashToG1(msg)
	e2, _ := h.Pair(vs)
	return e1.Equals(e2)
}

func containsDuplicateMessage(msgs [][]byte) bool {
	hashmap := make(map[string]bool)
	for i := 0; i < len(msgs); i++ {
		msg := string(msgs[i])
		if _, ok := hashmap[msg]; !ok {
			hashmap[msg] = true
		} else {
			return true
		}
	}
	return false
}
