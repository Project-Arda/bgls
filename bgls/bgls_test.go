// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"
	mathrand "math/rand"
	"testing"

	. "github.com/Project-Arda/bgls/curves"
	"github.com/stretchr/testify/assert"
)

var curves = []CurveSystem{Altbn128, Bls12}

func TestSingleSigner(t *testing.T) {
	for _, curve := range curves {
		sk, vk, err := KeyGen(curve)
		assert.Nil(t, err, "Key generation failed")
		assert.True(t, CheckAuthentication(curve, vk, Authenticate(curve, sk)), "Key Authentication failed")
		d := make([]byte, 64)
		_, err = rand.Read(d)
		assert.Nil(t, err, "test data generation failed")
		sig := Sign(curve, sk, d)
		assert.True(t, VerifySingleSignature(curve, vk, d, sig), "Point1 verification failed")

		sigTmp := sig.Copy()
		sigTmp, _ = sigTmp.Add(curve.GetG1())
		sig2 := sigTmp
		assert.False(t, VerifySingleSignature(curve, vk, d, sig2), "Point1 verification succeeding when it shouldn't")

		// TODO Add tests to show that this doesn't succeed if d or vk is altered
	}
}

func TestAggregation(t *testing.T) {
	for _, curve := range curves {
		N, Size := 6, 32
		msgs := make([][]byte, N+1)
		sigs := make([]Point, N+1)
		pubkeys := make([]Point, N+1)
		for i := 0; i < N; i++ {
			msgs[i] = make([]byte, Size)
			rand.Read(msgs[i])

			sk, vk, _ := KeyGen(curve)
			sig := Sign(curve, sk, msgs[i])
			pubkeys[i] = vk
			sigs[i] = sig
		}
		aggSig := AggregatePoints(sigs[:N])
		assert.True(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 verification failed")
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N-1], msgs[:N]),
			"Aggregate Point1 verification succeeding without enough pubkeys")
		skf, vkf, _ := KeyGen(curve)
		pubkeys[N] = vkf
		sigs[N] = Sign(curve, skf, msgs[0])
		msgs[N] = msgs[0]
		aggSig = AggregatePoints(sigs)
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys, msgs),
			"Aggregate Signature succeeding with duplicate messages")
		assert.True(t, VerifyAggregateKoskSignature(curve, aggSig, pubkeys, msgs),
			"Aggregate Kosk signature failing with duplicate messages")
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 succeeding with invalid signature")
		msgs[0] = msgs[1]
		msgs[1] = msgs[N]
		aggSig = AggregatePoints(sigs[:N])
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N]),
			"Aggregate Point1 succeeded with messages 0 and 1 switched")

		// TODO Add tests to make sure there is no mutation
	}
}

func TestMultiSig(t *testing.T) {
	for _, curve := range curves {
		Tests, Size, Signers := 5, 32, 10
		for i := 0; i < Tests; i++ {
			msg := make([]byte, Size)
			rand.Read(msg)
			signers := make([]Point, Signers)
			sigs := make([]Point, Signers)
			for j := 0; j < Signers; j++ {
				sk, vk, _ := KeyGen(curve)
				sigs[j] = Sign(curve, sk, msg)
				signers[j] = vk
			}
			aggSig := AggregatePoints(sigs)
			assert.True(t, VerifyMultiSignature(curve, aggSig, signers, msg),
				"Aggregate MultiSig verification failed")
			msg2 := make([]byte, Size)
			rand.Read(msg2)
			assert.False(t, VerifyMultiSignature(curve, aggSig, signers, msg2),
				"Aggregate MultiSig verification succeeded on incorrect msg")
			_, vkf, _ := KeyGen(curve)
			signers[0] = vkf
			assert.False(t, VerifyMultiSignature(curve, aggSig, signers, msg),
				"Aggregate MultiSig verification succeeded on incorrect signers")
		}
	}
}

func TestMultiSigWithMultiplicity(t *testing.T) {
	for _, curve := range curves {
		Tests, Size, Signers := 5, 32, 10
		for i := 0; i < Tests; i++ {
			msg := make([]byte, Size)
			rand.Read(msg)
			signers := make([]Point, Signers)
			sigs := make([]Point, Signers)
			multi := make([]int64, Signers)
			for j := 0; j < Signers; j++ {
				sk, vk, _ := KeyGen(curve)
				multi[j] = mathrand.Int63()
				sigs[j] = Sign(curve, sk, msg).Mul(big.NewInt(multi[j]))
				signers[j] = vk
			}
			aggSig := AggregatePoints(sigs)
			assert.True(t, VerifyMultiSignatureWithMultiplicity(curve, aggSig, signers, multi, msg),
				"Aggregate MultiSig verification failed")
			msg2 := make([]byte, Size)
			rand.Read(msg2)
			assert.False(t, VerifyMultiSignatureWithMultiplicity(curve, aggSig, signers, multi, msg2),
				"Aggregate MultiSig verification succeeded on incorrect msg")
			_, vkf, _ := KeyGen(curve)
			signers[0] = vkf
			assert.False(t, VerifyMultiSignatureWithMultiplicity(curve, aggSig, signers, multi, msg),
				"Aggregate MultiSig verification succeeded on incorrect signers")
		}
	}
}

func BenchmarkKeygen(b *testing.B) {
	b.ResetTimer()
	curve := Altbn128
	for i := 0; i < b.N; i++ {
		_, _, res := KeyGen(curve)
		if res != nil {
			b.Error("key gen failure")
		}
	}
}

func BenchmarkAltBnHashToCurve(b *testing.B) {
	curve := Altbn128
	ms := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		ms[i] = make([]byte, 64)
		rand.Read(ms[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		curve.HashToG1(ms[i])
	}
}

func BenchmarkSigning(b *testing.B) {
	curve := Altbn128
	sks := make([]*big.Int, b.N)
	ms := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		ms[i] = make([]byte, 64)
		rand.Read(ms[i])
		sk, _, _ := KeyGen(curve)
		sks[i] = sk
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Sign(curve, sks[i], ms[i])
	}
}

func BenchmarkVerification(b *testing.B) {
	curve := Altbn128
	message := make([]byte, 64)
	rand.Read(message)
	sk, vk, _ := KeyGen(curve)
	sig := Sign(curve, sk, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifySingleSignature(curve, vk, message, sig) {
			b.Error("verification failed")
		}
	}
}

var vks []Point
var sgs []Point
var msg []byte

func benchmulti(b *testing.B, k int) {
	curve := Altbn128
	multisig := MultiSig{vks[:k], AggregatePoints(sgs[:k]), msg}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !multisig.Verify(curve) {
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
	curve := Altbn128
	verifkeys := make([]Point, b.N)
	sigs := make([]Point, b.N)
	messages := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		messages[i] = make([]byte, 64)
		rand.Read(messages[i])
		sk, vk, _ := KeyGen(curve)
		verifkeys[i] = vk
		sigs[i] = Sign(curve, sk, messages[i])
	}
	aggsig := AggSig{verifkeys, messages, AggregatePoints(sigs)}
	b.ResetTimer()
	if !aggsig.Verify(curve) {
		b.Error("Aggregate verificaton failed")
	}
}
