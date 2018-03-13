# BGLS
Master: [![Build Status](https://travis-ci.org/Project-Arda/bgls.svg?branch=master)](https://travis-ci.org/Project-Arda/bgls)
Develop: [![Build Status](https://travis-ci.org/Project-Arda/bgls.svg?branch=develop)](https://travis-ci.org/Project-Arda/bgls)

Aggregate and Multi Signatures based on BGLS over Alt bn128

This library provides no security against side channel attacks. We provide no security guarantees of this implementation.

## Design
The goal of this library is to create an efficient and secure ad hoc aggregate and multi signature scheme. It relies on [alt bn128](https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256) for curve and pairing operations. It implements hashing of arbitrary byte data to curve points, the standard BGLS scheme for aggregate signatures, and a custom multi signature scheme.

### Multi Signature
The multi signature scheme is a modification of the BGLS scheme, where all signatures are on the same message. This allows verification with a constant number of pairing operations, at the cost of being insecure to chosen key attacks. To fix the chosen key attack, users are required to prove knowledge of their secret key, through the use of the Schnorr scheme applied to their public key.

## Curves
### Alt bn128

The group `G_1` is a cyclic group of prime order on the curve `Y^2 = X^3 + 3` defined over the field `F_p` with `p = 21888242871839275222246405745257275088696311157297823662689037894645226208583`.

The generator `g_1` is (1,2)

Since this curve is of prime order, every non-identity point is a generator, therefore the cofactor is 1.

The group `G_2` is a cyclic subgroup of the non-prime order elliptic curve `Y^2 = X^3 + 3*((i + 9)^(-1))` over the field `F_p^2 = F_p[X] / (X^2 + 1)` (where p is the same as above). We can write our irreducible element as `i`. The cofactor of this group is `21888242871839275222246405745257275088844257914179612981679871602714643921549`.

The generator `g_2` is defined as: `(11559732032986387107991004021392285783925812861821192530917403151452391805634*i + 10857046999023057135944570762232829481370756359578518086990519993285655852781, 4082367875863433681332203403145435568316851327593401208105741076214120093531*i + 8495653923123431417604973247489272438418190587263600148770280649306958101930)`

The identity element for both groups (The point at infinity in affine space) is internally represented as `(0,0)`

## Benchmarks
The following benchmarks are from a 3.80GHz i7-7700HQ CPU with 16GB ram. The aggregate verification which is utilizing parallelization for the pairing operations. The multisignature has parellilization for the two involved pairing operations, and parallelization for the pairing checks at the end.

For reference, the pairing operation (the slowest operation involved) takes ~1.6 milliseconds.
```
BenchmarkG1-8        	   10000	    141018 ns/op
BenchmarkG2-8        	    3000	    471002 ns/op
BenchmarkPairing-8   	    1000	   1609893 ns/op
PASS
ok  	github.com/ethereum/go-ethereum/crypto/bn256/cloudflare	4.725s
```

- `Signing` ~.22 milliseconds
- `Signature verification` ~3.4 milliseconds, using two pairings.
- `Multi Signature verification` ~3.7 milliseconds + ~2 microseconds per signer, two pairings + n point additions
- `Aggregate Signature verification` ~.2 milliseconds per signer/message pair, with n+1 pairings.

```
$ go test github.com/Project-Arda/bgls/  -v -bench .
BenchmarkKeygen-8                  	    3000	    434484 ns/op
BenchmarkAltBnHashToCurve-8        	   20000	     91947 ns/op
BenchmarkSigning-8                 	   10000	    218670 ns/op
BenchmarkVerification-8            	     500	   3079415 ns/op
BenchmarkMultiVerification64-8     	    1000	   2056798 ns/op
BenchmarkMultiVerification128-8    	    1000	   2140613 ns/op
BenchmarkMultiVerification256-8    	     500	   2334271 ns/op
BenchmarkMultiVerification512-8    	     500	   2617277 ns/op
BenchmarkMultiVerification1024-8   	     500	   3243045 ns/op
BenchmarkMultiVerification2048-8   	     300	   4325183 ns/op
BenchmarkAggregateVerification-8   	    5000	    361270 ns/op
PASS
ok  	github.com/Project-Arda/bgls	31.043s
```
For comparison, the ed25519 implementation in go yields much faster key generation signing and single signature verification. However, at ~145 microseconds per verification, the multi signature verification is actually faster beyond ~26 signatures.
```
$ go test golang.org/x/crypto/ed25519 -bench .
BenchmarkKeyGeneration-8   	   30000	     51878 ns/op
BenchmarkSigning-8         	   30000	     54050 ns/op
BenchmarkVerification-8    	   10000	    145063 ns/op
PASS
ok  	golang.org/x/crypto/ed25519	5.750s
```

### Hashing
The hashing algorithm is currently try-and-increment, and we support SHA3, Kangaroo twelve, Keccak256, and Blake2b.

We previously used a direct implementation of [Indifferentiable Hashing to Barreto–Naehrig Curves](http://www.di.ens.fr/~fouque/pub/latincrypt12.pdf) using blake2b. This was removed because it can't be implemented in the EVM due to gas costs, and because it will not work for BLS12-381.

## Future work
- Optimize bigint allocations.
- Add utility operations for serialization of keys/signatures.
- Implement a better Hashing algorithm, such as Elligator Squared.
- Integrate [BLS12-381](https://github.com/ebfull/pairing/tree/master/src/bls12_381) with go bindings.
- Integrations with [bgls-on-evm](https://github.com/jlandrews/bgls-on-evm).
- Add tests to show that none of the functions mutate data.
- More complete usage documentation.
- Add buffering for the channels used in parallelization.

## References
- Dan Boneh, Craig Gentry, Ben Lynn, and Hovav Shacham. [Aggregate and verifiably encrypted signatures from bilinear maps](https://www.iacr.org/archive/eurocrypt2003/26560416/26560416.pdf)
- Pierre-Alain Fouque and Mehdi Tibouchi. [Indifferentiable Hashing to
Barreto–Naehrig Curves](http://www.di.ens.fr/~fouque/pub/latincrypt12.pdf)
- Claus-Peter Schnorr. [Efficient Signature Generation by Smart Cards](https://pdfs.semanticscholar.org/3dfb/4764c0eaa69a12b78f3ec8736aae7e81de78.pdf)
