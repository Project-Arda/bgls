## Curves
This library currently supports Bls12-381, and Alt bn128. Currently it wraps existing golang libraries into a common interface, and provides hashing methods for these curves.
### Bls12-381

This is the set of curves which zcash is switching too. Its official documentation is located [here](https://github.com/ebfull/pairing/tree/master/src/bls12_381). The underlying `bls12-381` implementation used in this library is [dis2's repository](https://github.com/dis2/bls12).

### Alt bn128

The group `G_1` is a cyclic group of prime order on the curve `Y^2 = X^3 + 3` defined over the field `F_p` with `p = 21888242871839275222246405745257275088696311157297823662689037894645226208583`.

The generator `g_1` is (1,2)

Since this curve is of prime order, every non-identity point is a generator, therefore the cofactor is 1.

The group `G_2` is a cyclic subgroup of the non-prime order elliptic curve `Y^2 = X^3 + 3*((i + 9)^(-1))` over the field `F_p^2 = F_p[X] / (X^2 + 1)` (where p is the same as above). We can write our irreducible element as `i`. The cofactor of this group is `21888242871839275222246405745257275088844257914179612981679871602714643921549`.

The generator `g_2` is defined as: `(11559732032986387107991004021392285783925812861821192530917403151452391805634*i + 10857046999023057135944570762232829481370756359578518086990519993285655852781, 4082367875863433681332203403145435568316851327593401208105741076214120093531*i + 8495653923123431417604973247489272438418190587263600148770280649306958101930)`

The identity element for both groups (The point at infinity in affine space) is internally represented as `(0,0)`.

The underlying `alt bn128` implementation used in this library is [go-ethereums](https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256).

## Benchmarks
The following benchmarks are from a 3.80GHz i7-7700HQ CPU with 16GB ram.

The pairing operation on Altbn128 takes ~1.9 milliseconds.
```
BenchmarkPairing-8   	    1000	   1958898 ns/op
```
and for Bls12 it takes ~1.5 ms:
```
BenchmarkPairGT-8               	    1000	   1539918 ns/op
```

### Hashing
Currently only hashing to G1 is supported. Hashing to G2 is planned.
For altbn128, the hashing algorithm is currently try-and-increment, and we support SHA3, Kangaroo twelve, Keccak256, and Blake2b.

For bls12-381, we are using [Fouque-Tibouchi hashing](http://www.di.ens.fr/~fouque/pub/latincrypt12.pdf) using blake2b. This is interoperable with ebfull's repository.

## References
- Pierre-Alain Fouque and Mehdi Tibouchi. [Indifferentiable Hashing to
Barreto–Naehrig Curves](http://www.di.ens.fr/~fouque/pub/latincrypt12.pdf)
