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
//
// blsKosk.go implements Knowledge of secret key (Kosk) BLS. You do a proof to
// show that you know the secret key. This protects against the rogue public key
// attack.
//
// Proof of knowledge of the secret key is done in this library through
// doing a BLS signature on the public key itself as a message. There is a
// situation where this doesn't prove knowledge of the secret key. Suppose there
// is a BLS signing oracle for (pk1, sk1). Let pkA = -pk1 + x*g_2.
// Note that sig_pkA(pkA) = -sig_pk1(pkA) + xH(-pk1 + x*g_2)
// Consequently, if pk1 signs on pkA, this doesn't prove that person A knows skA
// and the rogue public key attack is possible as pkA is an authenticated key.
// One solution to fix this is to ensure that it
// is impossible for pk1 to sign the same pkA that is used in authentication.
// The way this is implemented here is to make the sign/verify methods prepend a
// 0x01 byte to any message that is being signed, and to make authentication
// prepend a null to public key before its signed. Since one would only ever
// authenticate their own public key, noone could get a signature from you that
// would work for their own authentication. (As all signatures you give out, other
// than your own authentication, have a 0x01 byte prepended instead of a null byte)
//
// Prepending bytes to ensure signing / authentication domain seperation sacrifices
// interoperability between KoskBls and normal BLS,
// however the advantage is that the authentications are aggregatable. They're
// aggregatable, since they are BLS signatures but all on distinct
// messages since they are distinct public keys.
//
// If you are using Kosk to secure against the rogue public key attack, you are
// intended to use: AggregateSignatures, KeyGen, KoskSign,
// KoskVerifySingleSignature, KoskVerifyMultiSignature
// KoskVerifyMultiSignatureWithMultiplicity, KoskVerifyAggregateSignature
//
// blsDistinctMessage.go implements the method of using Distinct Messages for aggregate signatures.
// This ensures that no two messages are used from separate pubkeys by prepending
// the public key before the message, thereby preventing the rogue public key
// attack.
//
// If you are using DistinctMsg to secure against the rogue public key attack, you are
// intended to use: AggregateSignatures, KeyGen, DistinctMsgSign,
// DistinctMsgVerifySingleSignature, DistinctMsgVerifyAggregateSignature
//
// The third method in Boneh's paper is dubbed "BLS with hashed aggregation exponents(HAE)" here,
// and is implemented in blsHAE.go. This is normal bls, but when aggregating
// you hash the `n` public keys to get `n` numbers in the range [0,2^(128)).
// Call these numbers t_0, t_1, ... t_{n-1}. Then you scale the ith signature to the
// by t_i, before multiplying them together.
//
// For Verification, you hash to obtain the same t_0, t_1, ... t_{n-1}, and scale
// the public keys accordingly. Then BLS proceeds as normal with these scaled public keys.
// Note that this method cannot aggregate pre-aggregated signatures. (I.e. you can only
// aggregate once), and it also requires inputing the keys into the hash function
// in the same order.
//
// The hash function from G^n \to \R^n is blake2x. The uncompressed marshal of every
// key is written to then blake2x instance. Then n 16 byte numbers are read from the XOF,
// each corresponding to a value of t.
//
// Note. I am calling this Hashed Aggregation Exponents in lieu of a better name
// for this defense against the rogue public key attack.
//
// If you are using HAE to secure against the rogue public key attack, you are
// intended to use: KeyGen, Sign, VerifySingleSignature, AggregateSignaturesWithHAE,
// VerifyMultiSignatureWithHAE, VerifyAggregateSignatureWithHAE
package bgls
