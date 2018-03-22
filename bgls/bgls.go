// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"

	. "github.com/Project-Arda/bgls/curves"
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
	x, err := rand.Int(rand.Reader, curve.GetG1Order())
	if err != nil {
		return nil, nil, err
	}
	pubKey := LoadPublicKey(curve, x)
	return x, pubKey, nil
}

//LoadPublicKey turns secret key into a public key of type Point2
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
	c := make(chan Point1)
	if len(sigs) == 2 {
		aggG1, _ := sigs[0].Add(sigs[1])
		return aggG1
	}
	aggSigs := make([]Point1, (len(sigs)/2)+(len(sigs)%2))
	counter := 0
	for i := 0; i < len(sigs); i += 2 { // No parallelization needed
		go concurrentAggregateG1(i, i+2, sigs, c)
		counter++
	}
	for i := 0; i < counter; i++ {
		aggSigs[i] = <-c
	}

	for {
		nxtAggSigs := make([]Point1, (len(aggSigs)/2)+(len(aggSigs)%2))
		counter = 0
		if len(aggSigs) == 1 {
			break
		}
		for i := 0; i < len(aggSigs); i += 2 {
			go concurrentAggregateG1(i, i+2, aggSigs, c)
			counter++
		}
		for i := 0; i < counter; i++ {
			nxtAggSigs[i] = <-c
		}
		aggSigs = nxtAggSigs
	}
	return aggSigs[0]
}

func concurrentAggregateG1(start int, end int, sigs []Point1, c chan Point1) {
	if end > len(sigs) {
		c <- sigs[start]
		return
	}
	summed, _ := sigs[start].Add(sigs[end-1])
	c <- summed
}

// AggregateG2 takes the sum of points on G2. This is used to sum a set of public keys for the multisignature
func AggregateG2(keys []Point2) Point2 {
	c := make(chan Point2)
	if len(keys) == 2 { // No parallelization needed
		aggG2, _ := keys[0].Add(keys[1])
		return aggG2
	}
	aggKeys := make([]Point2, (len(keys)/2)+(len(keys)%2))
	counter := 0
	for i := 0; i < len(keys); i += 2 {
		go concurrentAggregateG2(i, i+2, keys, c)
		counter++
	}
	for i := 0; i < counter; i++ {
		aggKeys[i] = <-c
	}

	for {
		nxtAggKeys := make([]Point2, (len(aggKeys)/2)+(len(aggKeys)%2))
		counter = 0
		if len(aggKeys) == 1 {
			break
		}
		for i := 0; i < len(aggKeys); i += 2 {
			go concurrentAggregateG2(i, i+2, aggKeys, c)
			counter++
		}
		for i := 0; i < counter; i++ {
			nxtAggKeys[i] = <-c
		}
		aggKeys = nxtAggKeys
	}
	return aggKeys[0]
}

func concurrentAggregateG2(start int, end int, keys []Point2, c chan Point2) {
	if end > len(keys) {
		c <- keys[start]
		return
	}
	summed, _ := keys[start].Add(keys[end-1])
	c <- summed
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
	c := make(chan PointT)
	c2 := make(chan PointT)
	go concurrentPair(curve, aggsig, curve.GetG2(), c2)
	for i := 0; i < len(msgs); i++ {
		go concurrentMsgPair(curve, msgs[i], keys[i], c)
	}
	e1 := <-c2
	e2 := <-c
	for i := 1; i < len(msgs); i++ {
		e3 := <-c
		e2, _ = e2.Add(e3)
	}
	return e1.Equals(e2)
}

func concurrentPair(curve CurveSystem, pt Point1, key Point2, c chan PointT) {
	targetPoint, _ := pt.Pair(key)
	c <- targetPoint
}

func concurrentMsgPair(curve CurveSystem, msg []byte, key Point2, c chan PointT) {
	h := curve.HashToG1(msg)
	targetPoint, _ := h.Pair(key)
	c <- targetPoint
}

//Verify checks that a single message has been signed by a set of keys
//vulnerable against chosen key attack, if keys have not been authenticated
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
