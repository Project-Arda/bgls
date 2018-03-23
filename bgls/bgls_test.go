// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"
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
		assert.True(t, Verify(curve, vk, d, sig), "Point1 verification failed")

		sigTmp := sig.Copy()
		sigTmp, _ = sigTmp.Add(curve.GetG1())
		sig2 := sigTmp
		assert.False(t, Verify(curve, vk, d, sig2), "Point1 verification succeeding when it shouldn't")

		// TODO Add tests to show that this doesn't succeed if d or vk is altered
	}
}

func TestAggregation(t *testing.T) {
	for _, curve := range curves {
		N, Size := 6, 32
		msgs := make([][]byte, N+1)
		sigs := make([]Point1, N+1)
		pubkeys := make([]Point2, N+1)
		for i := 0; i < N; i++ {
			msgs[i] = make([]byte, Size)
			rand.Read(msgs[i])

			sk, vk, _ := KeyGen(curve)
			sig := Sign(curve, sk, msgs[i])
			pubkeys[i] = vk
			sigs[i] = sig
		}
		aggSig := AggregateG1(sigs[:N])
		assert.True(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N], false),
			"Aggregate Point1 verification failed")
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N-1], msgs[:N], false),
			"Aggregate Point1 verification succeeding without enough pubkeys")
		skf, vkf, _ := KeyGen(curve)
		pubkeys[N] = vkf
		sigs[N] = Sign(curve, skf, msgs[0])
		msgs[N] = msgs[0]
		aggSig = AggregateG1(sigs)
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys, msgs, false),
			"Aggregate Point1 succeeding with duplicate messages with allow duplicates being false")
		assert.True(t, VerifyAggregateSignature(curve, aggSig, pubkeys, msgs, true),
			"Aggregate Point1 failing with duplicate messages with allow duplicates")
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N], false),
			"Aggregate Point1 succeeding with invalid signature")
		msgs[0] = msgs[1]
		msgs[1] = msgs[N]
		aggSig = AggregateG1(sigs[:N])
		assert.False(t, VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N], false),
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
			signers := make([]Point2, Signers)
			sigs := make([]Point1, Signers)
			for j := 0; j < Signers; j++ {
				sk, vk, _ := KeyGen(curve)
				sigs[j] = Sign(curve, sk, msg)
				signers[j] = vk
			}
			aggSig := AggregateG1(sigs)
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

// This is commented out because I just changed the hash implementation, so consistency
// is supposed to be broken with past implementations.
// func TestKnownCases(t *testing.T) {
// 	curve := Altbn128
// 	N := 3
// 	msgs := make([][]byte, N)
// 	msg1 := []byte{65, 20, 86, 143, 250}
// 	msg2 := []byte{157, 76, 30, 64, 128}
// 	msg3 := []byte{202, 255, 227, 59, 238}
// 	sk1, _ := new(big.Int).SetString("7830752896741750908830464020410322281763657818307273013205711220156049734883", 10)
// 	sk2, _ := new(big.Int).SetString("10065703961787583059826108098259128135713944641698809475150397710106034167549", 10)
// 	sk3, _ := new(big.Int).SetString("17145080297596291172729378766677038070724014074212589728874454474449054012678", 10)
//
// 	pubkeys := make([]Point2, N)
// 	vk1, vk2, vk3 := LoadPublicKey(curve, sk1), LoadPublicKey(curve, sk2), LoadPublicKey(curve, sk3)
// 	msgs[0], msgs[1], msgs[2] = msg1, msg2, msg3
// 	pubkeys[0], pubkeys[1], pubkeys[2] = vk1, vk2, vk3
//
// 	sigGen1 := Sign(curve, sk1, msgs[0])
// 	sigGen2 := Sign(curve, sk2, msgs[1])
// 	sigGen3 := Sign(curve, sk3, msgs[2])
// 	sigVal1_1, _ := new(big.Int).SetString("21637350149051642305293442272499488026428127697128429631193536777535027009518", 10)
// 	sigVal1_2, _ := new(big.Int).SetString("149479762519169687769683150632580363857094522511606512652585818657412262489", 10)
// 	sigVal2_1, _ := new(big.Int).SetString("14834848655731874780751719195269704123719987185153910215596714529658047741046", 10)
// 	sigVal2_2, _ := new(big.Int).SetString("5847895190688397897156144807293187828750812390735163763226617490736304595451", 10)
// 	sigVal3_1, _ := new(big.Int).SetString("21239057713889019692075876723610689006006025737755828182426488764514117409847", 10)
// 	sigVal3_2, _ := new(big.Int).SetString("11967902298809667109716532536825395835657143208987520118971083760489593281874", 10)
// 	sigChk1, _ := curve.MakeG1Point(sigVal1_1, sigVal1_2)
// 	sigChk2, _ := curve.MakeG1Point(sigVal2_1, sigVal2_2)
// 	sigChk3, _ := curve.MakeG1Point(sigVal3_1, sigVal3_2)
//
// 	assert.False(t, (!sigChk1.Equals(sigGen1) || !sigChk2.Equals(sigGen2) || !sigChk3.Equals(sigGen3)),
// 		"Recreating message signatures from known test cases failed")
//
// 	sigs := make([]Point1, N)
// 	sigs[0], sigs[1], sigs[2] = sigGen1, sigGen2, sigGen3
//
// 	aggSig1, _ := new(big.Int).SetString("12682380538491839124790562586247816360937861029087546329767912056050859037239", 10)
// 	aggSig2, _ := new(big.Int).SetString("5755139208159515629159661524903000057840676877654799839167369795924360592246", 10)
// 	aggSigChk, _ := curve.MakeG1Point(aggSig1, aggSig2)
//
// 	aggSig := AggregateG1(sigs)
// 	assert.True(t, aggSigChk.Equals(aggSig),
// 		"Aggregate Point1 does not match the known test case.")
// 	assert.True(t, VerifyAggregateSignature(curve, aggSig, pubkeys, msgs, false),
// 		"Aggregate Point1 verification failed")
// }

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
		if !Verify(curve, vk, message, sig) {
			b.Error("verification failed")
		}
	}
}

var vks []Point2
var sgs []Point1
var msg []byte

func benchmulti(b *testing.B, k int) {
	curve := Altbn128
	multisig := MultiSig{vks[:k], AggregateG1(sgs[:k]), msg}
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
	verifkeys := make([]Point2, b.N)
	sigs := make([]Point1, b.N)
	messages := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		messages[i] = make([]byte, 64)
		rand.Read(messages[i])
		sk, vk, _ := KeyGen(curve)
		verifkeys[i] = vk
		sigs[i] = Sign(curve, sk, messages[i])
	}
	aggsig := AggSig{verifkeys, messages, AggregateG1(sigs)}
	b.ResetTimer()
	if !aggsig.Verify(curve) {
		b.Error("Aggregate verificaton failed")
	}
}
