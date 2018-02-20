// Copyright (C) 2016 Jeremiah Andrews
// distributed under GNU GPLv3 license

package bgls

import (
	"crypto/rand"
	"os"
	"testing"
	"fmt"
)

func TestHashToCurve(t *testing.T) {
	N := 100
	msgs := make([][]byte, N)
	for i := 0; i < N; i++ {
		msgs[i] = make([]byte, N)
		_, _ = rand.Read(msgs[i])
		h1, res1 := HashToCurve(msgs[i])
		h2, res2 := HashToCurve(msgs[i])
		if !res1 || !res2 {
			t.Error("Hash to curve failure")
		}
		if !g1Equals(h1, h2) {
			t.Error("inconsistent results in HashToCurve")
		}
	}
}

func TestSingleSigner(t *testing.T) {
	sk, vk, err := KeyGen()
	if err != nil {
		t.Error("Key generation failed")
	}
	if !CheckAuthentication(vk, Authenticate(sk, vk)) {
		t.Error("Key Authentication failed")
	}
	d := make([]byte, 64)
	_, err = rand.Read(d)
	if err != nil {
		t.Error("test data generation failed")
	}
	sig := sk.Sign(d)
	if !Verify(vk, d, sig) {
		t.Error("Signature verification failed")
	}
	fmt.Println(sig.sig.Marshal())
	h, _ := HashToCurve(d)
	fmt.Println(h.Marshal())
	fmt.Println(vk.key.Marshal())
}

func BenchmarkKeygen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, res := KeyGen()
		if res != nil {
			b.Error("key gen failure")
		}
	}
}

func BenchmarkHashToCurve(b *testing.B) {
	ms := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		ms[i] = make([]byte, 64)
		_, _ = rand.Read(ms[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashToCurve(ms[i])
	}
}

func BenchmarkSigning(b *testing.B) {
	sks := make([]*SigningKey, b.N)
	ms := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		ms[i] = make([]byte, 64)
		_, _ = rand.Read(ms[i])
		sk, _, _ := KeyGen()
		sks[i] = sk
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sks[i].Sign(ms[i])
	}
}

func BenchmarkVerification(b *testing.B) {
	message := make([]byte, 64)
	_, _ = rand.Read(message)
	sk, vk, _ := KeyGen()
	sig := sk.Sign(message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(vk, message, sig) {
			b.Error("verification failed")
		}
	}
}

var vks []*VerifyKey
var sgs []*Signature
var msg []byte

func TestMain(m *testing.M) {
	vks = make([]*VerifyKey, 2048)
	sgs = make([]*Signature, 2048)
	msg = make([]byte, 64)
	_, _ = rand.Read(msg)
	for i := 0; i < 2048; i++ {
		sk, vk, _ := KeyGen()
		vks[i] = vk
		sgs[i] = sk.Sign(msg)
	}
	os.Exit(m.Run())
}

func benchmulti(b *testing.B, k int) {
	multisig := MultiSig{vks[:k], Aggregate(sgs[:k]), msg}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !multisig.Verify() {
			b.Error("MultiSig verification failed")
		}
	}
}

func BenchmarkMultiVerification64(b *testing.B) {
	benchmulti(b, 64)
}

func BenchmarkMultiVerification128(b *testing.B) {
	benchmulti(b, 128)
}

func BenchmarkMultiVerification256(b *testing.B) {
	benchmulti(b, 256)
}

func BenchmarkMultiVerification512(b *testing.B) {
	benchmulti(b, 512)
}

func BenchmarkMultiVerification1024(b *testing.B) {
	benchmulti(b, 1024)
}

func BenchmarkMultiVerification2048(b *testing.B) {
	benchmulti(b, 2048)
}

func BenchmarkAggregateVerification(b *testing.B) {
	verifkeys := make([]*VerifyKey, b.N)
	sigs := make([]*Signature, b.N)
	messages := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		messages[i] = make([]byte, 64)
		_, _ = rand.Read(messages[i])
		sk, vk, _ := KeyGen()
		verifkeys[i] = vk
		sigs[i] = sk.Sign(messages[i])
	}
	aggsig := AggSig{verifkeys, messages, Aggregate(sigs)}
	b.ResetTimer()
	if !aggsig.Verify() {
		b.Error("Aggregate verificaton failed")
	}
}
