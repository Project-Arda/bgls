// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestG1BlindingMatches(t *testing.T) {
	N := 100
	msgSize := 64
	for i := 0; i < N; i++ {
		msg := make([]byte, msgSize)
		_, _ = rand.Read(msg)

		p1 := Bls12.HashToG1(msg)
		p2 := Bls12.HashToG1Blind(msg)
		assert.True(t, p1.Equals(p2), "inconsistent results with BLS normal and blind hashing to G1")
	}
}

// Commented out because I'm unsure of the format test vectors will eventually be in
// func TestG1HashVectors(t *testing.T) {
// 	// Says whether or not to generate test vectors
// 	generate := false
// 	if generate {
// 		generateG1HashVectors()
// 	}
// }
//
// func generateG1HashVectors() {
// 	N := 100
// 	msgSize := 64
// 	output := make([]byte, 0, N*(msgSize+96))
// 	for i := 0; i < N; i++ {
// 		msg := make([]byte, msgSize)
// 		_, _ = rand.Read(msg)
// 		x, y := Bls12.HashToG1(msg).ToAffineCoords()
// 		xBytes := x.Bytes()
// 		yBytes := y.Bytes()
// 		coordinateBytes := make([]byte, 96)
// 		// This ensures that there are leading zeroes
// 		copy(coordinateBytes[48-len(xBytes):], xBytes)
// 		copy(coordinateBytes[96-len(yBytes):], yBytes)
// 		mutativeAppend(&output, msg)
// 		mutativeAppend(&output, coordinateBytes)
// 		// Newline
// 		mutativeAppend(&output, []byte("\n"))
// 	}
// 	os.Remove("testcases/bls12G1Hash.txt")
// 	ioutil.WriteFile("testcases/bls12G1Hash.txt", output, 0644)
// }
//
// func mutativeAppend(s *[]byte, msg []byte) {
// 	*s = append(*s, msg...)
// }
