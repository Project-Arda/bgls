// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package bgls

import (
	. "github.com/Project-Arda/bgls/curves" // nolint: golint
	"math/big"
	"strconv"
)

// Implementation of accountable-subgroup multisignatures (https://eprint.iacr.org/2018/483.pdf)
// The acronyms for these schemes are based upon the acronyms that were used inside the paper.

// TODO: write comments

func AmsCreateMembershipKeyShares(curve CurveSystem, sk *big.Int, curIndex int, pubkeys []Point) []Point {
	t := hashPubKeysToExponents(pubkeys)
	apk := AggregatePoints(ScalePoints(pubkeys, t))
	return AmsCreateMembershipKeySharesKnownExp(curve, sk, apk, t[curIndex], len(pubkeys))
}

func AmsCreateMembershipKeySharesKnownExp(curve CurveSystem, sk *big.Int, apk Point, exp *big.Int, numSigners int) []Point {
	shares := make([]Point, numSigners, numSigners)
	for i := 0; i < numSigners; i++ {
		shares[i] = SignCustHash(sk, []byte(strconv.Itoa(i)), getAmsH2(curve, apk))
		shares[i] = shares[i].Mul(exp)
	}
	return shares
}

func AmsAggregateMembershipKeyShares(curve CurveSystem, shares []Point) Point {
	return AggregatePoints(shares)
}

func AmsCreateSignatureShare(curve CurveSystem, sk *big.Int, membershipKey Point, msg []byte) Point {
	sig := SignCustHash(sk, msg, getAmsH0(curve))
	sig, _ = sig.Add(membershipKey)
	return sig
}

func AmsCombineSignatureShares(pubkeys []Point, sigs []Point) (aggKey Point, aggSig Point) {
	aggKey = AggregatePoints(pubkeys)
	aggSig = AggregateSignatures(sigs)
	return
}

func AmsVerifySignature(curve CurveSystem, apk Point, signers []int, aggKey Point, aggSig Point, msg []byte) bool {
	aggMsg := getAmsH2(curve, apk)([]byte(strconv.Itoa(signers[0])))
	for i := 1; i < len(signers); i++ {
		aggMsg, _ = aggMsg.Add(getAmsH2(curve, apk)([]byte(strconv.Itoa(signers[i]))))
	}
	aggPt, ok := curve.PairingProduct([]Point{getAmsH0(curve)(msg), aggMsg, aggSig.Mul(new(big.Int).SetInt64(-1))},
		[]Point{aggKey, apk, curve.GetG2()})
	if ok {
		return aggPt.Equals(curve.GetGTIdentity())
	}
	return ok
}

func AmsVerifySignatureWithSetCheck(curve CurveSystem, check func([]int) bool, apk Point, signers []int, aggKey Point, aggSig Point, msg []byte) bool {
	if check(signers) == false {
		return false
	}
	return AmsVerifySignature(curve, apk, signers, aggKey, aggSig, msg)
}

func AmspGetMessage(curve CurveSystem, pubkeys []Point, msg []byte) []byte {
	apk := getAggregatePubKey(curve, pubkeys)
	return append(apk.MarshalUncompressed(), msg...)
}

func getAmsH0(curve CurveSystem) func(msg []byte) Point {
	return func(msg []byte) Point {
		msg2 := append([]byte{0}, msg...)
		return curve.HashToG1(msg2)
	}
}

func getAmsH2(curve CurveSystem, apk Point) func(msg []byte) Point {
	return func(msg []byte) Point {
		msg2 := append(apk.MarshalUncompressed(), msg...)
		msg2 = append([]byte{1}, msg2...)
		return curve.HashToG1(msg2)
	}
}
