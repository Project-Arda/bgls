// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	"crypto/rand"
	"math/big"

	. "github.com/Project-Arda/bgls/curves" // nolint: golint
)

// Privkey holds the x,y pair
type Privkey struct {
	X *big.Int
	Y *big.Int
}

// Pubkey holds the u,v pair on G2
type Pubkey struct {
	U Point
	V Point
}

// Signature holds the data required to verify a bbsig.
type Signature struct {
	Sigma Point
	R     *big.Int
}

// KeyGen generates a private / public keypair for bbsigs.
// the points are on G2.
func KeyGen(curve CurveSystem) (Privkey, Pubkey) {
	x, _ := rand.Int(rand.Reader, curve.GetG1Order())
	y, _ := rand.Int(rand.Reader, curve.GetG1Order())
	sk := Privkey{x, y}
	key := LoadPublicKey(curve, x, y)
	return sk, key
}

// LoadPublicKey turns secret key into a public key
func LoadPublicKey(curve CurveSystem, x *big.Int, y *big.Int) Pubkey {
	u, v := curve.GetG2().Mul(x), curve.GetG2().Mul(y)
	return Pubkey{u, v}
}

// Sign creates a standard bbsigs signature on a message with a private key
func Sign(curve CurveSystem, sk Privkey, msg *big.Int) Signature {
	r, _ := rand.Int(rand.Reader, curve.GetG1Order())
	// Handle degenerate case of r = -(x+m)/y
	// This is tested as ry = -(x+m), to avoid the inversion
	// This check can be omitted in systems that require high performance,
	// since the probability of this occuring is 1/p.
	ry := new(big.Int).Mul(r, sk.Y)
	negXplusM := new(big.Int).Add(sk.X, msg)
	negXplusM.Sub(curve.GetG1Order(), negXplusM)
	if ry.Cmp(negXplusM) == 0 {
		return Sign(curve, sk, msg)
	}
	exp := new(big.Int).Mul(sk.Y, r)
	exp.Add(exp, sk.X)
	exp.Add(exp, msg)
	exp.ModInverse(exp, curve.GetG1Order())
	return Signature{curve.GetG1().Mul(exp), r}
}

// Verify checks that a standard bbsig is valid
func Verify(curve CurveSystem, sig Signature, pk Pubkey, msg *big.Int) bool {
	g2pt, _ := curve.GetG2().Mul(msg).Add(pk.U)
	g2pt, _ = g2pt.Add(pk.V.Mul(sig.R))
	res, _ := curve.Pair(sig.Sigma, g2pt)
	return res.Equals(curve.GetGT())
}
