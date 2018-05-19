package bgls

import (
	"math/big"

	. "github.com/Project-Arda/bgls/curves" // nolint: golint
	"golang.org/x/crypto/blake2b"
)

// SignHashed creates a BBSig with blake2b256 ran on the message
func SignHashed(curve CurveSystem, sk Privkey, msg []byte) Signature {
	return SignCustHash(curve, sk, msg, blake2b256)
}

// SignCustHash creates a BBSig with the provided hash function
func SignCustHash(curve CurveSystem, sk Privkey, msg []byte, hash func([]byte, *big.Int) *big.Int) Signature {
	return Sign(curve, sk, hash(msg, curve.GetG1Order()))
}

// VerifyHashed verifies a BBSig with blake2b256 ran on the message
func VerifyHashed(curve CurveSystem, sig Signature, pk Pubkey, msg []byte) bool {
	return VerifyCustHash(curve, sig, pk, msg, blake2b256)
}

// VerifyCustHash verifies a BBSig with the provided hash function
func VerifyCustHash(curve CurveSystem, sig Signature, pk Pubkey, msg []byte,
	hash func([]byte, *big.Int) *big.Int) bool {
	return Verify(curve, sig, pk, hash(msg, curve.GetG1Order()))
}

func blake2b256(msg []byte, p *big.Int) *big.Int {
	hashed := blake2b.Sum256(msg)
	res := new(big.Int).SetBytes(hashed[:])
	res.Mod(res, p)
	return res
}
