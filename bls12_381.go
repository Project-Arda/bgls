package bgls

import (
	"math/big"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/sha3"
)

var bls12_q, _ = new(big.Int).SetString("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 0)
var bls12_x, _ = new(big.Int).SetString("-0xd201000000010000", 0)
var bls12_a, _ = new(big.Int).SetString("0", 10)
var bls12_b, _ = new(big.Int).SetString("4", 10)
var bls12_cofactor = makeBls12Cofactor(bls12_x)

func makeBls12Cofactor(x *big.Int) *big.Int {
	x.Mod(x, bls12_q)
	x.Sub(x, one)
	x.Exp(x, x, two)
	x.Div(x, three)
	return x
}

func Bls12_sha3(message []byte) (p1, p2 *big.Int) {
	// TODO ADD COFACTOR MULTIPLICATION
	p1, p2 = hash64(message, sha3.Sum512, bls12_q, bls12_xToYSquared)
	return
}

func Bls12_blake2b(message []byte) (p1, p2 *big.Int) {
	// TODO ADD COFACTOR MULTIPLICATION
	p1, p2 = hash64(message, blake2b.Sum512, bls12_q, bls12_xToYSquared)
	return
}

func Bls12_kang12(message []byte) (p1, p2 *big.Int) {
	// TODO ADD COFACTOR MULTIPLICATION
	p1, p2 = hash64(message, kang12_64, bls12_q, bls12_xToYSquared)
	return
}

func bls12_xToYSquared(x *big.Int) *big.Int {
	result := new(big.Int)
	result.Exp(x, three, bls12_q)
	result.Add(result, bls12_b)
	return result
}
