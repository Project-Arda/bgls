// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"

	"math/big"
)

//SigningKey wraps secret exponent
type SigningKey struct {
	key *big.Int
}

//VerifyKey wraps public G2 curve point
type VerifyKey struct {
	key Point2
}

//Authentication is a proof of a valid VerifyKey
type Authentication struct {
	sig *Signature
}

//Signature Wraps G1 curve point as signature
type Signature struct {
	sig Point1
}

//MultiSig holds set of keys and one message plus signature
type MultiSig struct {
	keys []*VerifyKey
	sig  *Signature
	msg  []byte
}

//AggSig holds paired sequences of keys and messages, and one signature
type AggSig struct {
	keys []*VerifyKey
	msgs [][]byte
	sig  *Signature
}

//KeyGen generates a SigningKey and VerifyKey
func KeyGen(curve CurveSystem) (*SigningKey, *VerifyKey, error) {
	x, err := rand.Int(rand.Reader, curve.getG1Order())
	if err != nil {
		return nil, nil, err
	}
	sk, vk := LoadKey(curve, x)
	return sk, vk, nil
}

//LoadKey turns secret key into SigninKey and VerifyKey
func LoadKey(curve CurveSystem, x *big.Int) (*SigningKey, *VerifyKey) {
	v, _ := curve.G2Mul(x, curve.GetG2())
	vk := &VerifyKey{v}
	sk := &SigningKey{x}
	return sk, vk
}

// Authenticate generates an Authentication for a valid SigningKey/VerifyKey combo
// It signs a verification key with x.
func Authenticate(curve CurveSystem, x *SigningKey, v *VerifyKey) *Signature {
	return AuthenticateCustHash(curve, x, v, curve.HashToG1)
}

// AuthenticateCustHash generates an Authentication for a valid SigningKey/VerifyKey combo
// It signs a verification key with x. This runs with the specified hash function.
func AuthenticateCustHash(curve CurveSystem, x *SigningKey, v *VerifyKey, hash func([]byte) Point1) *Signature {
	m := curve.MarshalG2(v.key)
	return x.SignCustHash(curve, m, hash)
}

//CheckAuthentication verifies that this VerifyKey is valid
func CheckAuthentication(curve CurveSystem, v *VerifyKey, authentication *Signature) bool {
	return CheckAuthenticationCustHash(curve, v, authentication, curve.HashToG1)
}

//CheckAuthenticationCustHash verifies that this VerifyKey is valid, with the specified hash function
func CheckAuthenticationCustHash(curve CurveSystem, v *VerifyKey, authentication *Signature, hash func([]byte) Point1) bool {
	m := curve.MarshalG2(v.key)
	return VerifyCustHash(curve, v, m, authentication, hash)
}

//Sign creates a signature on a message with a private key
func (sk *SigningKey) Sign(curve CurveSystem, m []byte) *Signature {
	return sk.SignCustHash(curve, m, curve.HashToG1)
}

// SignCustHash creates a signature on a message with a private key, using
// a supplied function to hash to g1.
func (sk *SigningKey) SignCustHash(curve CurveSystem, m []byte, hash func([]byte) Point1) *Signature {
	h := hash(m)
	i, _ := curve.G1Mul(sk.key, h)
	return &Signature{i}
}

// Verify checks that a signature is valid
func Verify(curve CurveSystem, vk *VerifyKey, m []byte, sig *Signature) bool {
	return VerifyCustHash(curve, vk, m, sig, curve.HashToG1)
}

// Verify checks that a signature is valid
func VerifyCustHash(curve CurveSystem, vk *VerifyKey, m []byte, sig *Signature, hash func([]byte) Point1) bool {
	h := hash(m)
	p1, _ := curve.Pair(h, vk.key)
	p2, _ := curve.Pair(sig.sig, curve.GetG2())
	return curve.GTEquals(p1, p2)
}

// Aggregate turns a set of signatures into a single signature
func Aggregate(curve CurveSystem, sigs []*Signature) *Signature {
	a := curve.CopyG1(sigs[0].sig)
	for _, s := range sigs[1:] {
		a, _ = curve.G1Add(a, s.sig)
	}
	return &Signature{a}
}

// Verify checks that all messages were signed by associated keys
// Will fail under duplicate messages
func (a AggSig) Verify(curve CurveSystem) bool {
	return VerifyAggregateSignature(curve, a.sig, a.keys, a.msgs, false)
}

// VerifyAggregateSignature verifies that the aggregated signature proves that all messages were signed by associated keys
// Will fail under duplicate messages, unless allow duplicates is True.
func VerifyAggregateSignature(curve CurveSystem, aggsig *Signature, keys []*VerifyKey, msgs [][]byte, allowDuplicates bool) bool {
	if len(keys) != len(msgs) {
		return false
	}
	if !allowDuplicates {
		if containsDuplicateMessage(msgs) {
			return false
		}
	}
	e1, _ := curve.Pair(aggsig.sig, curve.GetG2())
	h := curve.HashToG1(msgs[0])
	e2, _ := curve.Pair(h, keys[0].key)
	for i := 1; i < len(msgs); i++ {
		h = curve.HashToG1(msgs[i])
		e3, _ := curve.Pair(h, keys[i].key)
		e2, _ = curve.GTAdd(e3, e2)
	}
	return curve.GTEquals(e1, e2)
}

//Verify checks that a single message has been signed by a set of keys
//vulnerable against chosen key attack, if keys have not been authenticated
func (m MultiSig) Verify(curve CurveSystem) bool {
	return VerifyMultiSignature(curve, m.sig, m.keys, m.msg)
}

// VerifyMultiSignature checks that the aggregate signature correctly proves that a single message has been signed by a set of keys,
// vulnerable against chosen key attack, if keys have not been authenticated
func VerifyMultiSignature(curve CurveSystem, aggsig *Signature, keys []*VerifyKey, msg []byte) bool {
	e1, _ := curve.Pair(aggsig.sig, curve.GetG2())
	vs := curve.CopyG2(keys[0].key)
	for i := 1; i < len(keys); i++ {
		vs, _ = curve.G2Add(vs, keys[i].key)
	}
	h := curve.HashToG1(msg)
	e2, _ := curve.Pair(h, vs)
	return curve.GTEquals(e1, e2)
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
