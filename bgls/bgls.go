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

// VerifySingleSignature checks that a signature is valid
func VerifySingleSignature(curve CurveSystem, pubKey Point2, m []byte, sig Point1) bool {
	return VerifySingleSignatureCustHash(curve, pubKey, m, sig, curve.HashToG1)
}

// VerifySingleSignatureCustHash checks that a signature is valid with the supplied hash function
func VerifySingleSignatureCustHash(curve CurveSystem, pubKey Point2, msg []byte, sig Point1, hash func([]byte) Point1) bool {
	c := make(chan PointT)
	go concurrentPair(curve, sig, curve.GetG2(), c)
	go concurrentMsgPair(curve, msg, pubKey, c)
	e1 := <-c
	e2 := <-c
	return e1.Equals(e2)
}

// AggregateG1 takes the sum of points on G1. This is used to convert a set of signatures into a single signature
func AggregateG1(sigs []Point1) Point1 {
	if len(sigs) == 2 { // No parallelization needed
		aggG1, _ := sigs[0].Add(sigs[1])
		return aggG1
	}
	// Aggregate all the g1 signatures together using concurrency
	c := make(chan Point1)
	aggSigs := make([]Point1, (len(sigs)/2)+(len(sigs)%2))
	counter := 0

	// Initialize aggsigs to an array with signatures being the sum of two
	// adjacent signatures.
	for i := 0; i < len(sigs); i += 2 {
		go concurrentAggregateG1(i, sigs, c)
		counter++
	}
	for i := 0; i < counter; i++ {
		aggSigs[i] = <-c
	}

	// Keep on aggregating every pair of signatures until only one signature remains
	for {
		nxtAggSigs := make([]Point1, (len(aggSigs)/2)+(len(aggSigs)%2))
		counter = 0
		if len(aggSigs) == 1 {
			break
		}
		for i := 0; i < len(aggSigs); i += 2 {
			go concurrentAggregateG1(i, aggSigs, c)
			counter++
		}
		for i := 0; i < counter; i++ {
			nxtAggSigs[i] = <-c
		}
		aggSigs = nxtAggSigs
	}
	return aggSigs[0]
}

// concurrentAggregateG1 handles the channel for concurrent Aggregation of g1 points.
// It only adds the element at keys[start] and keys[start + 1], and sends it through the channel
func concurrentAggregateG1(start int, sigs []Point1, c chan Point1) {
	if start+1 >= len(sigs) {
		c <- sigs[start]
		return
	}
	summed, _ := sigs[start].Add(sigs[start+1])
	c <- summed
}

// AggregateG2 takes the sum of points on G2. This is used to sum a set of public keys for the multisignature
func AggregateG2(keys []Point2) Point2 {
	if len(keys) == 2 { // No parallelization needed
		aggG2, _ := keys[0].Add(keys[1])
		return aggG2
	}
	// Aggregate all the g2 points together using concurrency
	c := make(chan Point2)
	aggKeys := make([]Point2, (len(keys)/2)+(len(keys)%2))
	counter := 0

	// Initialize aggKeys to an array with elements being the sum of two
	// adjacent Point 2's.
	for i := 0; i < len(keys); i += 2 {
		go concurrentAggregateG2(i, keys, c)
		counter++
	}
	for i := 0; i < counter; i++ {
		aggKeys[i] = <-c
	}

	// Keep on aggregating every pair of keys until only one aggregate key remains
	for {
		nxtAggKeys := make([]Point2, (len(aggKeys)/2)+(len(aggKeys)%2))
		counter = 0
		if len(aggKeys) == 1 {
			break
		}
		for i := 0; i < len(aggKeys); i += 2 {
			go concurrentAggregateG2(i, aggKeys, c)
			counter++
		}
		for i := 0; i < counter; i++ {
			nxtAggKeys[i] = <-c
		}
		aggKeys = nxtAggKeys
	}
	return aggKeys[0]
}

// concurrentAggregateG2 handles the channel for concurrent Aggregation of g2 points.
// It only adds the element at keys[start] and keys[start + 1], and sends it through the channel
func concurrentAggregateG2(start int, keys []Point2, c chan Point2) {
	if start+1 >= len(keys) {
		c <- keys[start]
		return
	}
	summed, _ := keys[start].Add(keys[start+1])
	c <- summed
}

func (a *AggSig) Verify(curve CurveSystem) bool {
	return VerifyAggregateSignature(curve, a.sig, a.keys, a.msgs)
}

// VerifyAggregateSignature verifies that the aggregated signature proves that all messages were signed by associated keys
// Will fail if there are duplicate messages, due to the possibility of the rogue public-key attack.
// If duplicate messages should be allowed, one of the protections against the rogue public-key attack should be used
// such as Knowledge of Secret Key (Kosk), enforcing distinct messages, or the method discussed
// here <https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html>
func VerifyAggregateSignature(curve CurveSystem, aggsig Point1, keys []Point2, msgs [][]byte) bool {
	return verifyAggSig(curve, aggsig, keys, msgs, false)
}

func verifyAggSig(curve CurveSystem, aggsig Point1, keys []Point2, msgs [][]byte, allowDuplicates bool) bool {
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

// concurrentPair pairs pt with key, and sends the result down the channel.
func concurrentPair(curve CurveSystem, pt Point1, key Point2, c chan PointT) {
	targetPoint, _ := pt.Pair(key)
	c <- targetPoint
}

// concurrentMsgPair hashes the message, pairs it with key, and sends the result down the channel.
func concurrentMsgPair(curve CurveSystem, msg []byte, key Point2, c chan PointT) {
	h := curve.HashToG1(msg)
	concurrentPair(curve, h, key, c)
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

type indexedPoint2 struct {
	index int
	pt    Point2
}

func scalePublicKeys(keys []Point2, factors []*big.Int) (newKeys []Point2) {
	if factors == nil {
		return keys
	} else if len(keys) != len(factors) {
		return nil
	}
	newKeys = make([]Point2, len(keys))
	c := make(chan *indexedPoint2)
	for i := 0; i < len(keys); i++ {
		go concurrentScale(keys[i], factors[i], i, c)
	}
	for i := 0; i < len(keys); i++ {
		pt := <-c
		newKeys[pt.index] = pt.pt
	}
	return newKeys
}

func concurrentScale(key Point2, factor *big.Int, index int, c chan *indexedPoint2) {
	if factor == nil {
		c <- &indexedPoint2{index, key.Copy()}
	} else {
		c <- &indexedPoint2{index, key.Mul(factor)}
	}
}
