# Bgls

This implements bgls signatures using the curves interface. This also implements all three methods for securing against the rogue public key attack as described in Dan Boneh's paper https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html.

## Definitions
### Aggregate Signature
An aggregate signature allows you to take signatures for different messages, and combine them into a single signature of the same size as each of the original signatures. This aggregate signature will verify all of the message / signature pairs that compose it. There is one attack on aggregate signatures, called the rogue public key attack. There are three defense mechanisms that eliminate the attacks possibility, and they are described in the next section. Note that aggregate signatures can also be aggregated together.

This takes `n+1` pairing operations, where `n` is the number of message / signature pairs which the aggregate signature proves.
### Multi-Signature
A multi-signature is an aggregate signature where all the signatures are over the same message. Due to how bgls signatures work, this allows for the entire signatures to be verified in 2 pairings, regardless of how many signatures are aggregated together. This allows for very efficient verification.

## Protections against the Rogue Public key attack
More documentation is provided in the godocs.
### Enforcing distinct messages
This is implemented in `DistinctMessage.go`. This ensures that no two messages are used from separate pubkeys by prepending
 the public key before the message, thereby preventing the rogue public key attack. However this sacrifices the efficient multisig verifications, since all messages are distinct.

If you are using DistinctMsg to secure against the rogue public key attack, you are intended to use: _AggregateSignatures, KeyGen, DistinctMsgSign, DistinctMsgVerifySingleSignature, DistinctMsgVerifyAggregateSignatureature_

### Knowledge of Secret Key (Kosk)
This is implemented in `blsKosk.go`. It uses a BLS signature on the public key to prove knowledge of the secret key. This method requires an authentication to be published before its corresponding public key can be used. These authentications maintain aggregatability (even with other signatures), however due to security considerations as described within the godocs, signatures produced from Kosk are not cross-compatible with that of normal BLS.

To use Kosk to secure against the rogue public key attack, you are
intended to use: _AggregateSignatures, KeyGen, KoskSign, KoskVerifySingleSignature, KoskVerifyMultiSignature KoskVerifyMultiSignatureWithMultiplicity, KoskVerifyAggregateSignature_

### BLS with hashed aggregation exponents (HAE)
This is the third method for protecting against the rogue public key attack, as described in Boneh's paper. It is implemented in `blsHAE.go`. This method of securing against the rogue public key attack has the upside of not requiring an authentication message and still allowing for efficient multisignature verification. However more information needs to be collected to aggregate already aggregated HAE signatures. (Since you would have to know which signatures went into each of the component aggregate signatures, and in what order they appeared.)

This method relies on a hash function from `G^n \to \R^n`. This library uses blake2x, where each key in `G^n` is written one after another, and then `n*16` bytes are read from the XOF. The authors of this library know of no standard currently, if a standard hash function for this method is chosen, then this library will switch to that. However this hash satisfies the criterion laid out in Boneh's paper. We can remove the need for knowing the order in which signatures went into the hash function by sorting by the public keys in the hash, and using the sorted list throughout. Currently we don't need to worry about the order and that overhead, but we can implement this. 

Note. This is called Hashed Aggregation Exponents in lieu of an official name for this defense against the rogue public key attack.

If you are using HAE to secure against the rogue public key attack, you are intended to use: _KeyGen, Sign, VerifySingleSignature, AggregateSignaturesWithHAE, VerifyMultiSignatureWithHAE, VerifyAggregateSignatureWithHAE_

## Benchmarks
These still need to be created.

## References
- Dan Boneh [Methods to prevent the rogue public key attack](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html)
- Dan Boneh, Craig Gentry, Ben Lynn, and Hovav Shacham. [Aggregate and verifiably encrypted signatures from bilinear maps](https://www.iacr.org/archive/eurocrypt2003/26560416/26560416.pdf)
