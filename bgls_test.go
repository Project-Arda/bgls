// Copyright (C) 2016 Jeremiah Andrews
// distributed under GNU GPLv3 license

package bgls

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"
)

func TestAltBnHashToCurve(t *testing.T) {
	N := 10
	msgs := make([][]byte, N)
	for i := 0; i < N; i++ {
		msgs[i] = make([]byte, N)
		_, _ = rand.Read(msgs[i])
		x1, y1 := Altbn_sha3(msgs[i])
		x2, y2 := Altbn_sha3(msgs[i])
		if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
			t.Error("inconsistent results in altbn sha3 hash")
		}

		x1, y1 = Altbn_kang12(msgs[i])
		x2, y2 = Altbn_kang12(msgs[i])
		if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
			t.Error("inconsistent results in altbn kang12 hash")
		}

		x1, y1 = Altbn_blake2b(msgs[i])
		x2, y2 = Altbn_blake2b(msgs[i])
		if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
			t.Error("inconsistent results in altbn blake2b hash")
		}

		p1 := Altbn_HashToCurve(msgs[i])
		p2 := Altbn_HashToCurve(msgs[i])
		if !g1Equals(p1, p2) {
			t.Error("inconsistent results in Altbn HashToCurve")
		}
	}
}

func TestBls12_sha3(t *testing.T) {
	// Tests consistency
	// TODO test correctness against known test cases.
	N := 10
	msgs := make([][]byte, N)
	for i := 0; i < N; i++ {
		msgs[i] = make([]byte, N)
		_, _ = rand.Read(msgs[i])
		x1, x2 := Bls12_sha3(msgs[i])
		y1, y2 := Bls12_sha3(msgs[i])
		if x1.Cmp(y1) != 0 || x2.Cmp(y2) != 0 {
			t.Error("inconsistent results in bls12 sha3 hash")
		}

		x1, x2 = Bls12_kang12(msgs[i])
		y1, y2 = Bls12_kang12(msgs[i])
		if x1.Cmp(y1) != 0 || x2.Cmp(y2) != 0 {
			t.Error("inconsistent results in bls12 kang12 hash")
		}

		x1, x2 = Bls12_blake2b(msgs[i])
		y1, y2 = Bls12_blake2b(msgs[i])
		if x1.Cmp(y1) != 0 || x2.Cmp(y2) != 0 {
			t.Error("inconsistent results in bls12 blake2b hash")
		}
	}
}

func TestEthereumHash(t *testing.T) {
	a := []byte{116, 101, 115, 116}
	x, y := Altbn_keccak3(a)
	exp_x, _ := new(big.Int).SetString("634489172570043803084693618096875920319784881922983678883461805150451460743", 10)
	exp_y, _ := new(big.Int).SetString("15164142362807052582232776116457640322025300091343369508144366426999358332749", 10)
	if x.Cmp(exp_x) != 0 || y.Cmp(exp_y) != 0 {
		t.Error("Hash does not match known Ethereum Output")
	}
	pt := Altbn_HashToCurve(a)
	x2, y2 := AltBnG1ToCoord(pt)
	if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
		t.Error("Conversion of point to coordinates is not working")
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

	sigTmp := copyg1(sig.sig)
	sigTmp.Add(sigTmp, g1)
	sig2 := &Signature{sigTmp}
	if Verify(vk, d, sig2) {
		t.Error("Signature verification succeeding when it shouldn't")
	}

	// TODO Add tests to show that this doesn't succeed if d or vk is altered
}

// func TestAltBnPairing(t *testing.T) {
// 	N := 10
// 	Size : = 32
// 	msgs := make([][]byte, 2*N)
// 	for i := 0; i < N; i++ {
// 		msgs[i] = make([]byte, Size)
// 		msgs[N+i] = make([]byte, Size)
// 		_, _ = rand.Read(msgs[i])
// 		_, _ = rand.Read(msgs[N+i])
//
// 		sk1, vk1, err1 := KeyGen()
// 		sk2, vk2, err2 := KeyGen()
// 	}
// }

func BenchmarkKeygen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, res := KeyGen()
		if res != nil {
			b.Error("key gen failure")
		}
	}
}

func BenchmarkAltBnHashToCurve(b *testing.B) {
	ms := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		ms[i] = make([]byte, 64)
		_, _ = rand.Read(ms[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Altbn_HashToCurve(ms[i])
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
