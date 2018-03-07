// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"
)

func TestAltbnHashToCurve(t *testing.T) {
	curve := Altbn128
	N := 10
	msgs := make([][]byte, N)
	for i := 0; i < N; i++ {
		msgs[i] = make([]byte, N)
		_, _ = rand.Read(msgs[i])

		testHashConsistency(AltbnSha3, "altbn sha3 hash", msgs[i], t)
		testHashConsistency(AltbnKang12, "altbn kang12 hash", msgs[i], t)
		testHashConsistency(AltbnBlake2b, "altbn blake2b hash", msgs[i], t)

		p1 := curve.HashToG1(msgs[i])
		p2 := curve.HashToG1(msgs[i])
		if !p1.Equals(p2) {
			t.Error("inconsistent results in Altbn HashToCurve")
		}
	}
}

// func TestBls12Hashing(t *testing.T) {
// 	// Tests consistency
// 	N := 10
// 	msgs := make([][]byte, N)
// 	for i := 0; i < N; i++ {
// 		msgs[i] = make([]byte, N)
// 		_, _ = rand.Read(msgs[i])
// 		testHashConsistency(Bls12Sha3, "bls12 sha3 hash", msgs[i], t)
// 		testHashConsistency(Bls12Kang12, "bls12 kang12 hash", msgs[i], t)
// 		testHashConsistency(Bls12Blake2b, "bls12 blake2b hash", msgs[i], t)
// 	}
// }

func testHashConsistency(hashFunc func(message []byte) (p1, p2 *big.Int), hashname string, msg []byte, t *testing.T) {
	x1, y1 := hashFunc(msg)
	x2, y2 := hashFunc(msg)
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.Error("inconsistent results in " + hashname)
	}
}

func TestEthereumHash(t *testing.T) {
	curve := Altbn128
	// Tests Altbn hash to curve against known solidity test case.
	a := []byte{116, 101, 115, 116}
	x, y := AltbnKeccak3(a)
	expX, _ := new(big.Int).SetString("634489172570043803084693618096875920319784881922983678883461805150451460743", 10)
	expY, _ := new(big.Int).SetString("15164142362807052582232776116457640322025300091343369508144366426999358332749", 10)
	if x.Cmp(expX) != 0 || y.Cmp(expY) != 0 {
		t.Error("Hash does not match known Ethereum Output")
	}
	pt := curve.HashToG1(a)
	x2, y2 := pt.ToAffineCoords()
	if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
		t.Error("Conversion of point to coordinates is not working")
	}
}

func TestSingleSigner(t *testing.T) {
	curve := Altbn128
	sk, vk, err := KeyGen(curve)
	if err != nil {
		t.Error("Key generation failed")
	}
	if !CheckAuthentication(curve, vk, Authenticate(curve, sk)) {
		t.Error("Key Authentication failed")
	}
	d := make([]byte, 64)
	_, err = rand.Read(d)
	if err != nil {
		t.Error("test data generation failed")
	}
	sig := Sign(curve, sk, d)
	if !Verify(curve, vk, d, sig) {
		t.Error("Point1 verification failed")
	}

	sigTmp := sig.Copy()
	sigTmp, _ = sigTmp.Add(curve.GetG1())
	sig2 := sigTmp
	if Verify(curve, vk, d, sig2) {
		t.Error("Point1 verification succeeding when it shouldn't")
	}

	// TODO Add tests to show that this doesn't succeed if d or vk is altered
}

func TestAggregation(t *testing.T) {
	curve := Altbn128
	N := 6
	Size := 32
	msgs := make([][]byte, N+1)
	sigs := make([]Point1, N+1)
	pubkeys := make([]Point2, N+1)
	for i := 0; i < N; i++ {
		msgs[i] = make([]byte, Size)
		_, _ = rand.Read(msgs[i])

		sk, vk, _ := KeyGen(curve)
		sig := Sign(curve, sk, msgs[i])
		pubkeys[i] = vk
		sigs[i] = sig
	}
	aggSig := AggregateG1(sigs[:N])
	if !VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N], false) {
		t.Error("Aggregate Point1 verification failed")
	}
	if VerifyAggregateSignature(curve, aggSig, pubkeys[:N-1], msgs[:N], false) {
		t.Error("Aggregate Point1 verification succeeding without enough pubkeys")
	}
	skf, vkf, _ := KeyGen(curve)
	pubkeys[N] = vkf
	sigs[N] = Sign(curve, skf, msgs[0])
	msgs[N] = msgs[0]
	aggSig = AggregateG1(sigs)
	if VerifyAggregateSignature(curve, aggSig, pubkeys, msgs, false) {
		t.Error("Aggregate Point1 succeeding with duplicate messages with allow duplicates being false")
	}
	if !VerifyAggregateSignature(curve, aggSig, pubkeys, msgs, true) {
		t.Error("Aggregate Point1 failing with duplicate messages with allow duplicates")
	}
	if VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N], false) {
		t.Error("Aggregate Point1 succeeding with invalid signature")
	}
	msgs[0] = msgs[1]
	msgs[1] = msgs[N]
	aggSig = AggregateG1(sigs[:N])
	if VerifyAggregateSignature(curve, aggSig, pubkeys[:N], msgs[:N], false) {
		t.Error("Aggregate Point1 succeeded with messages 0 and 1 switched")
	}

	// TODO Add tests to make sure there is no mutation
}

func TestMultiSig(t *testing.T) {
	curve := Altbn128
	Tests := 5
	Size := 32
	Signers := 10
	for i := 0; i < Tests; i++ {
		msg := make([]byte, Size)
		_, _ = rand.Read(msg)
		signers := make([]Point2, Signers)
		sigs := make([]Point1, Signers)
		for j := 0; j < Signers; j++ {
			sk, vk, _ := KeyGen(curve)
			sigs[j] = Sign(curve, sk, msg)
			signers[j] = vk
		}
		aggSig := AggregateG1(sigs)
		if !VerifyMultiSignature(curve, aggSig, signers, msg) {
			t.Error("Aggregate MultiSig verification failed")
		}
		msg2 := make([]byte, Size)
		_, _ = rand.Read(msg2)
		if VerifyMultiSignature(curve, aggSig, signers, msg2) {
			t.Error("Aggregate MultiSig verification succeeded on incorrect msg")
		}
		_, vkf, _ := KeyGen(curve)
		signers[0] = vkf
		if VerifyMultiSignature(curve, aggSig, signers, msg) {
			t.Error("Aggregate MultiSig verification succeeded on incorrect signers")
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
		_, _ = rand.Read(ms[i])
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
		_, _ = rand.Read(ms[i])
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
	_, _ = rand.Read(message)
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

func TestMain(m *testing.M) {
	curve := Altbn128
	vks = make([]Point2, 2048)
	sgs = make([]Point1, 2048)
	msg = make([]byte, 64)
	_, _ = rand.Read(msg)
	for i := 0; i < 2048; i++ {
		sk, vk, _ := KeyGen(curve)
		vks[i] = vk
		sgs[i] = Sign(curve, sk, msg)
	}
	os.Exit(m.Run())
}

func TestMarshal(t *testing.T) {
	curve := Altbn128
	marshalled := curve.GetG1().Marshal()
	if g1, ok := curve.UnmarshalG1(marshalled); ok {
		if !g1.Equals(curve.GetG1()) {
			t.Error("Unmarshalling G1 is not consistent with Marshal G1")
		}
	} else {
		t.Error("Unmarshalling G1 failed")
	}
	marshalled = marshalled[1:]
	if _, ok := curve.UnmarshalG1(marshalled); ok {
		t.Error("Unmarshalling G1 is succeeding when the byte array is of the wrong length")
	}

	marshalled = curve.GetG2().Marshal()
	if g2, ok := curve.UnmarshalG2(marshalled); ok {
		if !g2.Equals(curve.GetG2()) {
			t.Error("Unmarshalling G2 is not consistent with Marshal G2")
		}
	} else {
		t.Error("Unmarshalling G2 failed")
	}
	marshalled = marshalled[1:]
	if _, ok := curve.UnmarshalG2(marshalled); ok {
		t.Error("Unmarshalling G2 is succeeding when the byte array is of the wrong length")
	}

	marshalled = curve.GetGT().Marshal()
	if gT, ok := curve.UnmarshalGT(marshalled); ok {
		if !gT.Equals(curve.GetGT()) {
			t.Error("Unmarshalling GT is not consistent with Marshal GT")
		}
	} else {
		t.Error("Unmarshalling GT failed")
	}
	marshalled = marshalled[1:]
	if _, ok := curve.UnmarshalGT(marshalled); ok {
		t.Error("Unmarshalling GT is succeeding when the byte array is of the wrong length")
	}
}

func TestKnownCases(t *testing.T) {
	curve := Altbn128
	N := 3
	msgs := make([][]byte, N)
	msg1 := []byte{65, 20, 86, 143, 250}
	msg2 := []byte{157, 76, 30, 64, 128}
	msg3 := []byte{202, 255, 227, 59, 238}
	sk1, _ := new(big.Int).SetString("7830752896741750908830464020410322281763657818307273013205711220156049734883", 10)
	sk2, _ := new(big.Int).SetString("10065703961787583059826108098259128135713944641698809475150397710106034167549", 10)
	sk3, _ := new(big.Int).SetString("17145080297596291172729378766677038070724014074212589728874454474449054012678", 10)

	pubkeys := make([]Point2, N)
	vk1 := LoadPublicKey(curve, sk1)
	vk2 := LoadPublicKey(curve, sk2)
	vk3 := LoadPublicKey(curve, sk3)
	msgs[0] = msg1
	msgs[1] = msg2
	msgs[2] = msg3

	pubkeys[0] = vk1
	pubkeys[1] = vk2
	pubkeys[2] = vk3

	sigGen1 := Sign(curve, sk1, msgs[0])
	sigGen2 := Sign(curve, sk2, msgs[1])
	sigGen3 := Sign(curve, sk3, msgs[2])
	sigVal1_1, _ := new(big.Int).SetString("21637350149051642305293442272499488026428127697128429631193536777535027009518", 10)
	sigVal1_2, _ := new(big.Int).SetString("149479762519169687769683150632580363857094522511606512652585818657412262489", 10)
	sigVal2_1, _ := new(big.Int).SetString("14834848655731874780751719195269704123719987185153910215596714529658047741046", 10)
	sigVal2_2, _ := new(big.Int).SetString("5847895190688397897156144807293187828750812390735163763226617490736304595451", 10)
	sigVal3_1, _ := new(big.Int).SetString("21239057713889019692075876723610689006006025737755828182426488764514117409847", 10)
	sigVal3_2, _ := new(big.Int).SetString("11967902298809667109716532536825395835657143208987520118971083760489593281874", 10)
	sigChk1, _ := curve.MakeG1Point(sigVal1_1, sigVal1_2)
	sigChk2, _ := curve.MakeG1Point(sigVal2_1, sigVal2_2)
	sigChk3, _ := curve.MakeG1Point(sigVal3_1, sigVal3_2)

	if !sigChk1.Equals(sigGen1) || !sigChk2.Equals(sigGen2) || !sigChk3.Equals(sigGen3) {
		t.Error("Recreating message signatures from known test cases failed")
	}

	sigs := make([]Point1, N)
	sigs[0] = sigGen1
	sigs[1] = sigGen2
	sigs[2] = sigGen3

	aggSig1, _ := new(big.Int).SetString("12682380538491839124790562586247816360937861029087546329767912056050859037239", 10)
	aggSig2, _ := new(big.Int).SetString("5755139208159515629159661524903000057840676877654799839167369795924360592246", 10)
	aggSigChk, _ := curve.MakeG1Point(aggSig1, aggSig2)

	aggSig := AggregateG1(sigs)
	if !aggSigChk.Equals(aggSig) {
		t.Error("Aggregate Point1 does not match the known test case.")
	}
	if !VerifyAggregateSignature(curve, aggSig, pubkeys, msgs, false) {
		t.Error("Aggregate Point1 verification failed")
	}
}

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
		_, _ = rand.Read(messages[i])
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
