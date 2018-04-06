// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

// Package bgls implements bls signatures, as described by
// Short Signatures from the Weil Pairing. In this library, an aggregate signature
// refers to an aggregation of signatures on different messages into a single signature.
// A multi signature refers to an aggregation of signatures on the same message
// into the same signature. The difference is that a multi signature can be
// verified quite quickly, using 2 pairing operations regardless of the number
// of signers, whereas an aggregate signature requires n+1 pairing operations.
//
// There are three different
// methods to protect against the rogue public key attack. The three methods are
// proving knowledge of secret key (kosk), enforcing that all messages are distinct
// (Distinct Message), and using a hash of the public keys to create exponents
// that are used in aggregation (Hashed Aggregation Exponents - HAE). These are
// all described in https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html,
// where HAE is Dan Boneh's new method introduced in that article.
//
// Proof of knowledge of the secret key is done in this library through
// doing a BLS signature on the public key itself as a message. See blsKosk.go
// for more details. Note that this Kosk method is not interoperable with 'plain'
// bls due to design choices explained in blsKosk.go
//
// BLS with distinct messages is done in this library by prepending the public
// key to each message, before signing, to ensure that it each message is unique.
// (thereby circumventing rogue public key attacks). See blsDistinctMessage.go
// for more details. Note that BLS with distinct messages does not offer multi
// sigs in their efficiently computable form where only 2 pairings are required.
//
// The third method for preventing the rogue public key attack is explained in
// in blsHAE.go, and in Boneh's paper. The method for hashing public keys to the
// exponents is to write them to blake2x, and then to squeeze the corresponding
// amount of output from the XOF.
//
package bgls
