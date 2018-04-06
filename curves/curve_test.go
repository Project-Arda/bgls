// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"bufio"
	"crypto/rand"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"

	b64 "encoding/base64"

	"github.com/stretchr/testify/assert"
)

var curves = []CurveSystem{Altbn128, Bls12}

func TestMarshal(t *testing.T) {
	for _, curve := range curves {
		numTests := 16
		requiredScalars := []*big.Int{big.NewInt(1), Altbn128.GetG1Order()}
		for i := 0; i < numTests; i++ {
			scalar, _ := rand.Int(rand.Reader, curve.GetG1Order())
			if i < len(requiredScalars) {
				scalar = requiredScalars[i]
			}

			mulg1 := curve.GetG1().Mul(scalar)
			marshalled := mulg1.Marshal()
			if recoveredG1, ok := curve.UnmarshalG1(marshalled); ok {
				assert.True(t, recoveredG1.Equals(mulg1),
					"Unmarshalling G1 is not consistent with Marshal G1")
			} else {
				t.Error("Unmarshalling G1 failed")
			}
			marshalled = mulg1.MarshalUncompressed()
			if recoveredG1, ok := curve.UnmarshalG1(marshalled); ok {
				assert.True(t, recoveredG1.Equals(mulg1),
					"Unmarshalling G1 is not consistent with MarshalUncompressed G1")
			} else {
				t.Error("Unmarshalling G1 failed")
			}
			marshalled = marshalled[1:]
			if _, ok := curve.UnmarshalG1(marshalled); ok {
				t.Error("Unmarshalling G1 is succeeding when the byte array is of the wrong length")
			}

			mulg2 := curve.GetG2().Mul(scalar)
			marshalled = mulg2.Marshal()
			if recoveredG2, ok := curve.UnmarshalG2(marshalled); ok {
				assert.True(t, recoveredG2.Equals(mulg2),
					"Unmarshalling G2 is not consistent with Marshal G2")
			} else {
				t.Error("Unmarshalling G2 failed on scalar " + scalar.String())
			}
			marshalled = mulg2.Marshal()
			if recoveredG2, ok := curve.UnmarshalG2(marshalled); ok {
				assert.True(t, recoveredG2.Equals(mulg2),
					"Unmarshalling G2 is not consistent with MarshalUncompressed G2")
			} else {
				t.Error("Unmarshalling G2 failed on scalar " + scalar.String())
			}
			marshalled = marshalled[1:]
			if _, ok := curve.UnmarshalG2(marshalled); ok {
				t.Error("Unmarshalling G2 is succeeding when the byte array is of the wrong length")
			}

			mulgT, _ := curve.Pair(mulg1, curve.GetG2())
			marshalled = mulgT.Marshal()
			if recoveredGT, ok := curve.UnmarshalGT(marshalled); ok {
				assert.True(t, recoveredGT.Equals(mulgT),
					"Unmarshalling GT is not consistent with Marshal GT")
			} else {
				t.Error("Unmarshalling GT failed")
			}
			marshalled = marshalled[1:]
			if _, ok := curve.UnmarshalGT(marshalled); ok {
				t.Error("Unmarshalling GT is succeeding when the byte array is of the wrong length")
			}
		}
	}
}

func TestMakePoint(t *testing.T) {
	for _, curve := range curves {
		numTests := 10
		requiredScalars := []*big.Int{big.NewInt(1), Altbn128.GetG1Order()}
		for i := 0; i < numTests; i++ {
			scalar, _ := rand.Int(rand.Reader, curve.GetG1Order())
			if i < len(requiredScalars) {
				scalar = requiredScalars[i]
			}

			mulg1 := curve.GetG1().Mul(scalar)
			coords := mulg1.ToAffineCoords()
			if recoveredG1, ok := curve.MakeG1Point(coords, true); ok {
				assert.True(t, recoveredG1.Equals(mulg1),
					"Making G1 points is not consistent with G1.ToAffineCoords()")
			} else {
				t.Error("Making G1 point failed on scalar " + scalar.String())
			}

			mulg2 := curve.GetG2().Mul(scalar)
			coords = mulg2.ToAffineCoords()
			if recoveredG2, ok := curve.MakeG2Point(coords, true); ok {
				assert.True(t, recoveredG2.Equals(mulg2),
					"Making G2 points is not consistent with G2.ToAffineCoords()")
			} else {
				t.Error("Making G2 point failed on scalar " + scalar.String())
			}
		}
	}
}

func TestMul(t *testing.T) {
	// TODO: Create known test cases specific to each curve from another library.
	for _, curve := range curves {
		numTests := 32
		requiredScalars := []*big.Int{zero, one}
		for i := 0; i < numTests; i++ {
			scalar, _ := rand.Int(rand.Reader, curve.GetG1Order())
			if i < len(requiredScalars) {
				scalar = requiredScalars[i]
			}
			scalarNeg := new(big.Int).Sub(zero, scalar)
			pt1 := curve.GetG1().Mul(scalar)
			pt2 := curve.GetG1().Mul(scalarNeg)
			inf, _ := pt1.Add(pt2)
			assert.True(t, inf.Equals(curve.GetG1Infinity()))
			pt1 = curve.GetG2().Mul(scalar)
			pt2 = curve.GetG2().Mul(scalarNeg)
			inf, _ = pt1.Add(pt2)
			assert.True(t, inf.Equals(curve.GetG2Infinity()))
		}
	}
}

func TestPairingProd(t *testing.T) {
	// TODO: Make upstream libraries include proper product of pairing functionality
	for _, curve := range curves {
		numTests := 5
		for i := 0; i < numTests; i++ {
			numPoints := 5
			points1 := make([]Point, numPoints)
			points2 := make([]Point, numPoints)
			prod := curve.GetGTIdentity()
			for j := 0; j < numPoints; j++ {
				g1Scalar, _ := rand.Int(rand.Reader, curve.GetG1Order())
				g2Scalar, _ := rand.Int(rand.Reader, curve.GetG1Order())

				points1[j] = curve.GetG1().Mul(g1Scalar)
				points2[j] = curve.GetG2().Mul(g2Scalar)
				pair, _ := curve.Pair(points1[j], points2[j])
				prod, _ = prod.Add(pair)
			}
			pairCheck, _ := curve.PairingProduct(points1, points2)
			assert.True(t, pairCheck.Equals(prod))
		}
	}
}

func TestAggregation(t *testing.T) {
	for _, curve := range curves {
		for _, N := range []int{2, 4, 6, 8} {
			g1 := make([]Point, N)
			g2 := make([]Point, N)
			sum := new(big.Int).SetInt64(0)
			for i := 0; i < N; i++ {
				x, _ := rand.Int(rand.Reader, curve.GetG1Order())
				sum.Add(sum, x)
				sum.Mod(sum, curve.GetG1Order())
				g1[i] = curve.GetG1().Mul(x)
				g2[i] = curve.GetG2().Mul(x)
			}
			aggG1 := AggregatePoints(g1)
			aggG2 := AggregatePoints(g2)
			assert.True(t, aggG1.Equals(curve.GetG1().Mul(sum)), curve.Name()+" "+strconv.Itoa(N))
			assert.True(t, aggG2.Equals(curve.GetG2().Mul(sum)), curve.Name()+" "+strconv.Itoa(N))
		}
	}
}

func TestScaling(t *testing.T) {
	N := 5
	for _, curve := range curves {
		for _, g := range []Point{curve.GetG1(), curve.GetG2()} {
			pts1 := make([]Point, N)
			pts2 := make([]Point, N)
			factors := make([]*big.Int, N)
			for i := 0; i < N; i++ {
				x, _ := rand.Int(rand.Reader, curve.GetG1Order())
				pts1[i] = g.Mul(x)
				f, _ := rand.Int(rand.Reader, curve.GetG1Order())
				pts2[i] = pts1[i].Copy().Mul(f)
				factors[i] = f
			}
			pts1 = ScalePoints(pts1, factors)
			for i := 0; i < N; i++ {
				assert.True(t, pts1[i].Equals(pts2[i]))
			}
		}
	}
}

func TestG1HashVectors(t *testing.T) {
	for _, curve := range curves {
		// Says whether or not to generate test vectors
		generate := false
		if generate {
			generateG1HashVectors(curve)
		}
		file, err := os.Open("testcases/" + curve.Name() + "G1Hash.dat")
		if err != nil {
			t.Error(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			s := strings.Split(line, ",")
			msg, err1 := b64.StdEncoding.DecodeString(s[0])
			marshalledPt, err2 := b64.StdEncoding.DecodeString(s[1])
			if err1 != nil || err2 != nil {
				t.Error("Incorrectly formatted test vector file " + err.Error())
			}
			chkPt := curve.HashToG1(msg)
			pt, ok := curve.UnmarshalG1(marshalledPt)
			if !ok {
				t.Error("Error in unmarshalling point")
			}
			assert.True(t, pt.Equals(chkPt))
		}

		if err := scanner.Err(); err != nil {
			t.Error(err)
		}
	}
}

func generateG1HashVectors(curve CurveSystem) {
	NumberOfTests := 10
	msgSize := 64
	output := make([]byte, 0, NumberOfTests*(msgSize+96))
	for i := 0; i < NumberOfTests; i++ {
		msg := make([]byte, msgSize)
		_, _ = rand.Read(msg)
		pt := curve.HashToG1(msg)
		// Make the created format for these:
		// base64(msg),base64(Uncompressed Marshal of HashToG1(msg))
		// Note that there is no space between the two base64'd messages.
		mutativeAppend(&output, []byte(b64.StdEncoding.EncodeToString(msg)))
		mutativeAppend(&output, []byte(","))
		mutativeAppend(&output, []byte(b64.StdEncoding.EncodeToString(pt.MarshalUncompressed())))
		mutativeAppend(&output, []byte("\n"))
	}
	// Delete old file it exists
	os.Remove("testcases/" + curve.Name() + "G1Hash.dat")
	ioutil.WriteFile("testcases/"+curve.Name()+"G1Hash.dat", output, 0644)
}

// Mutatively appends msg to s. This is used to avoid having to reallocate more memory for s.
func mutativeAppend(s *[]byte, msg []byte) {
	*s = append(*s, msg...)
}
