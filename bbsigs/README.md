# Boneh-Boyen Signatures

This implements the [BB14] signature scheme based upon bilinear maps which does not assume the random oracle model. Instead it uses the Strong Diffie Hellman (SDH) assumption. This signature scheme ends up being far more concretely efficient in signature creation and verification than single BLS signatures (However, BLS multisigs end up being faster after a threshold number of signers). The security of a signature in this scheme is `sqrt(p/d)`, where `p` is the order of the G1 and G2, and `d` is the number of signatures provided for a given public key\*. This `1/sqrt(d)` term comes from attacks on `SDH`. [Cheon06]

This signature scheme is named BB signatures here, due to authors being Dan Boneh and Xavier Boyen. If there is an official alternate name for this signature scheme, this folder will be renamed.

TODO write and implement partial message recovery.


## Documentation

## Benchmarks
These still need to be created.

\* technically `d` is the number of adaptive signature queries which an adversary can make on the public key.

## References
[BB14] [Short Signatures Without Random Oracles and the SDH Assumption in Bilinear Groups](https://crypto.stanford.edu/~dabo/papers/bbsigs.pdf), Dan Boneh, Xavier Boyen 2014
[Cheon06] [Security Analysis of the Strong Diffie-Hellman Problem](https://iacr.org/archive/eurocrypt2006/40040001/40040001.pdf), Jung Hee Cheon 2006
