// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"

	"github.com/dchest/blake2b"

	"math/big"

	"github.com/ethereum/go-ethereum/crypto/bn256"

	"bytes"
)

//SigningKey wraps secret exponent
type SigningKey struct {
	key *big.Int
}

//VerifyKey wraps public G2 curve point
type VerifyKey struct {
	key *bn256.G2
}

//Authentication is a proof of a valid VerifyKey
type Authentication struct {
	t *bn256.G2
	r *big.Int
}

//Signature Wraps G1 curve point as signature
type Signature struct {
	sig *bn256.G1
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

var g1 = new(bn256.G1).ScalarBaseMult(one)
var g2 = new(bn256.G2).ScalarBaseMult(one)

//KeyGen generates a SigningKey and VerifyKey
func KeyGen() (*SigningKey, *VerifyKey, error) {
	x, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, nil, err
	}
	sk, vk := LoadKey(x)
	return sk, vk, nil
}

//LoadKey turns secret key into SigninKey and VerifyKey
func LoadKey(x *big.Int) (*SigningKey, *VerifyKey) {
	v := new(bn256.G2).ScalarBaseMult(x)
	vk := &VerifyKey{v}
	sk := &SigningKey{x}
	return sk, vk
}

//Authenticate generates an Authentication for a valid SigningKey/VerifyKey combo
func Authenticate(x *SigningKey, v *VerifyKey) *Authentication {
	k, _ := rand.Int(rand.Reader, bn256.Order)
	t := new(bn256.G2).ScalarBaseMult(k)
	H := blake2b.New256()
	H.Write(v.key.Marshal())
	H.Write(t.Marshal())
	cb := make([]byte, 32)
	H.Sum(cb)
	c := new(big.Int)
	c.SetBytes(cb)
	c.Mod(c, bn256.Order)
	r := new(big.Int).Mul(c, x.key)
	r.Mod(r, bn256.Order)
	r.Neg(r)
	r.Add(r, k)
	r.Mod(r, bn256.Order)
	return &Authentication{t, r}
}

//CheckAuthentication verifies that this VerifyKey is valid
func CheckAuthentication(v *VerifyKey, a *Authentication) bool {
	H := blake2b.New256()
	H.Write(v.key.Marshal())
	H.Write(a.t.Marshal())
	cb := make([]byte, 32)
	H.Sum(cb)
	c := new(big.Int)
	c.SetBytes(cb)
	c.Mod(c, bn256.Order)
	gr := new(bn256.G2).ScalarBaseMult(a.r)
	vc := new(bn256.G2).ScalarMult(v.key, c)
	tprime := new(bn256.G2).Add(gr, vc)
	return g2Equals(a.t, tprime)
}

//Sign creates a signature on a message with a private key
func (sk *SigningKey) Sign(m []byte) *Signature {
	h := AltbnHashToCurve(m)
	return &Signature{h.ScalarMult(h, sk.key)}
}

// Verify checks that a signature is valid
func Verify(vk *VerifyKey, m []byte, sig *Signature) bool {
	h := AltbnHashToCurve(m)
	return pairEquals(bn256.Pair(h, vk.key), bn256.Pair(sig.sig, g2))
}

// Aggregate turns a set of signatures into a single signature
func Aggregate(sigs []*Signature) *Signature {
	a := copyg1(sigs[0].sig)
	for _, s := range sigs[1:] {
		a.Add(a, s.sig)
	}
	return &Signature{a}
}

// Verify checks that all messages were signed by associated keys
// Will fail under duplicate messages
func (a AggSig) Verify() bool {
	return VerifyAggregateSignature(a.sig, a.keys, a.msgs, false)
}

// VerifyAggregateSignature verifies that the aggregated signature proves that all messages were signed by associated keys
// Will fail under duplicate messages, unless allow duplicates is True.
func VerifyAggregateSignature(aggsig *Signature, keys []*VerifyKey, msgs [][]byte, allowDuplicates bool) bool {
	if len(keys) != len(msgs) {
		return false
	}
	if !allowDuplicates {
		if containsDuplicateMessage(msgs) {
			return false
		}
	}
	e1 := bn256.Pair(aggsig.sig, g2)
	h := AltbnHashToCurve(msgs[0])
	e2 := bn256.Pair(h, keys[0].key)
	for i := 1; i < len(msgs); i++ {
		h = AltbnHashToCurve(msgs[i])
		e2.Add(e2, bn256.Pair(h, keys[i].key))
	}
	return pairEquals(e1, e2)
}

//Verify checks that a single message has been signed by a set of keys
//vulnerable against chosen key attack, if keys have not been authenticated
func (m MultiSig) Verify() bool {
	return VerifyMultiSignature(m.sig, m.keys, m.msg)
}

// VerifyMultiSignature checks that the aggregate signature correctly proves that a single message has been signed by a set of keys,
// vulnerable against chosen key attack, if keys have not been authenticated
func VerifyMultiSignature(aggsig *Signature, keys []*VerifyKey, msg []byte) bool {
	e1 := bn256.Pair(aggsig.sig, g2)
	vs := copyg2(keys[0].key)
	for i := 1; i < len(keys); i++ {
		vs.Add(vs, keys[i].key)
	}
	h := AltbnHashToCurve(msg)
	e2 := bn256.Pair(h, vs)
	return pairEquals(e1, e2)
}

func pairEquals(a, b *bn256.GT) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}
func g1Equals(a, b *bn256.G1) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}
func g2Equals(a, b *bn256.G2) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}
func copyg1(x *bn256.G1) *bn256.G1 {
	p, _ := new(bn256.G1).Unmarshal(x.Marshal())
	return p
}
func copyg2(x *bn256.G2) *bn256.G2 {
	p, _ := new(bn256.G2).Unmarshal(x.Marshal())
	return p
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
