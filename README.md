# bgls
Aggregate and Multi Signatures based on BGLS over BN256

WIP / not for production use (in need of expert review/audit)

## Design
The goal of this library is to create an efficient and secure ad hoc aggregate and multi signature scheme. It relies on [bn256](https://godoc.org/golang.org/x/crypto/bn256) for curve and pairing operations. It implements hashing of arbitrary byte data to curve points, the standard BGLS scheme for aggregate signatures, and a custom multi signature scheme.

### Hashing
The hashing algorithm is a direct implementation of [Indifferentiable Hashing to
Barreto–Naehrig Curves](http://www.di.ens.fr/~fouque/pub/latincrypt12.pdf) using blake2b

### Multi Signature
The multi signature scheme is a modification of the BGLS scheme, where all signatures are on the same message. This allows verification with a constant number of pairing operations, at the cost of being insecure to chosen key attacks. To fix the chosen key attack, users are required to prove knowledge of their secret key, through the use of the Schnorr scheme applied to their public key.

## Benchmarks
The following benchmarks are from a 2.40GHz i7-4700MQ CPU with 16GB ram.

For reference, the pairing operation (the slowest operation involved) takes ~18 milliseconds.
```
go test golang.org/x/crypto/bn256 -bench .
BenchmarkPairing-8           100          17912498 ns/op
PASS
ok      golang.org/x/crypto/bn256       2.173s
```
- `Signing` ~4 milliseconds
- `Signature verification` ~40 milliseconds, using two pairings.
- `Multi Signature verification` ~40 milliseconds + ~40 microseconds per signer, two pairings + n point additions
- `Aggregate Signature verification` ~20 milliseconds per signer/message pair, with n+1 pairings.

```
go test github.com/jlandrews/bgls -v -bench .
=== RUN   TestHashToCurve
--- PASS: TestHashToCurve (0.14s)
=== RUN   TestSingleSigner
--- PASS: TestSingleSigner (0.07s)
BenchmarkKeygen-8                            200           6840239 ns/op
BenchmarkHashToCurve-8                      2000            620408 ns/op
BenchmarkSigning-8                           300           4079951 ns/op
BenchmarkVerification-8                       30          43311116 ns/op
BenchmarkMultiVerification64-8                30          46442746 ns/op
BenchmarkMultiVerification128-8               30          47066510 ns/op
BenchmarkMultiVerification256-8               30          52626693 ns/op
BenchmarkMultiVerification512-8               20          61672295 ns/op
BenchmarkMultiVerification1024-8              20          81409695 ns/op
BenchmarkMultiVerification2048-8              10         120849410 ns/op
BenchmarkAggregateVerification-8             100          21439108 ns/op
PASS
ok      github.com/jlandrews/bgls	45.431s
```
For comparison, the ed25519 implementation in go yields much faster key generation signing and single signature verification. At ~150 microseconds per verification, the multi signature verification is actually faster beyond ~500 signatures.
```
go test golang.org/x/crypto/ed25519 -bench .
BenchmarkKeyGeneration-8           30000             59385 ns/op
BenchmarkSigning-8                 20000             61220 ns/op
BenchmarkVerification-8            10000            155311 ns/op
PASS
ok      golang.org/x/crypto/ed25519     5.894s
```

## Future work
- Use a faster pairing implementation. (ideally with gpu support for batch pairing)
- Optimize bigint allocations in HashToCurve.
- Add utility operations for serialization of keys/signatures.



## References
- Dan Boneh, Craig Gentry, Ben Lynn, and Hovav Shacham. [Aggregate and verifiably encrypted signatures from bilinear maps](https://www.iacr.org/archive/eurocrypt2003/26560416/26560416.pdf)
- Pierre-Alain Fouque and Mehdi Tibouchi. [Indifferentiable Hashing to
Barreto–Naehrig Curves](http://www.di.ens.fr/~fouque/pub/latincrypt12.pdf)
- Claus-Peter Schnorr. [Efficient Signature Generation by Smart Cards](https://pdfs.semanticscholar.org/3dfb/4764c0eaa69a12b78f3ec8736aae7e81de78.pdf)
