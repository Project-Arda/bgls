// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package curves

import (
	"math/big"
)

// *complexNum is a complex number whose elements are members of field of size p
// This is essentially an element of Fp[i]/(i^2 + 1)
type complexNum struct {
	im, re *big.Int // value is ai+b, where a,b \in Fp
}

func getComplexZero() *complexNum {
	return &complexNum{new(big.Int).SetInt64(0), new(big.Int).SetInt64(0)}
}

func (result *complexNum) Add(num *complexNum, other *complexNum, p *big.Int) *complexNum {
	result.im.Add(num.im, other.im)
	result.re.Add(num.re, other.re)
	result.im.Mod(result.im, p)
	result.re.Mod(result.re, p)
	return result
}

func (result *complexNum) Conjugate(num *complexNum) *complexNum {
	result.re.Set(num.re)
	result.im.Sub(zero, num.im)
	return result
}

func (result *complexNum) Mul(num *complexNum, other *complexNum, p *big.Int) *complexNum {
	real := new(big.Int).Mul(num.re, other.re)
	real.Sub(real, new(big.Int).Mul(num.im, other.im))
	imag := new(big.Int).Mul(num.im, other.re)
	imag.Add(imag, new(big.Int).Mul(num.re, other.im))
	real.Mod(real, p)
	imag.Mod(imag, p)
	result.im = imag
	result.re = real
	return result
}

func (result *complexNum) MulScalar(num *complexNum, other *big.Int, p *big.Int) *complexNum {
	real := new(big.Int).Mul(num.re, other)
	real.Mod(real, p)
	result.re = real
	result.im = num.im
	return result
}

func (result *complexNum) Square(num *complexNum, p *big.Int) *complexNum {
	real := new(big.Int).Exp(num.re, two, p)
	real.Sub(real, new(big.Int).Exp(num.im, two, p))
	real.Mod(real, p)
	imag := new(big.Int).Mul(num.im, num.re)
	imag.Mul(two, imag)
	imag.Mod(imag, p)
	result.im = imag
	result.re = real
	return result
}

func (result *complexNum) Set(num *complexNum) *complexNum {
	result.im.Set(num.im)
	result.re.Set(num.re)
	return result
}

func (result *complexNum) Exp(base *complexNum, power *big.Int, p *big.Int) *complexNum {
	sum := &complexNum{new(big.Int).SetInt64(0), new(big.Int).SetInt64(1)}
	t := getComplexZero()
	for i := power.BitLen() - 1; i >= 0; i-- {
		t.Square(sum, p)
		if power.Bit(i) != 0 {
			sum.Mul(t, base, p)
		} else {
			sum.Set(t)
		}
	}
	result.im = sum.im
	result.re = sum.re
	return result
}

func (result *complexNum) Equals(other *complexNum) bool {
	if result.im.Cmp(other.im) != 0 || result.re.Cmp(other.re) != 0 {
		return false
	}
	return true
}
