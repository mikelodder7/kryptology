//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package bbs is an implementation of BBS+ signature of https://eprint.iacr.org/2016/663.pdf
package bbs

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// Signature is a BBS+ signature
// as described in 4.3 in
// <https://eprint.iacr.org/2016/663.pdf>
type Signature struct {
	a    curves.PairingPoint
	e, s curves.Scalar
}

// Init creates an empty signature to a specific curve
// which should be followed by UnmarshalBinary or Create.
func (sig *Signature) Init(curve *curves.PairingCurve) *Signature {
	sig.a = curve.NewG1IdentityPoint()
	sig.e = curve.NewScalar()
	sig.s = curve.NewScalar()
	return sig
}

func (sig Signature) MarshalBinary() ([]byte, error) {
	out := append(sig.a.ToAffineCompressed(), sig.e.Bytes()...)
	out = append(out, sig.s.Bytes()...)
	return out, nil
}

func (sig *Signature) UnmarshalBinary(data []byte) error {
	pointLength := len(sig.a.ToAffineCompressed())
	scalarLength := len(sig.s.Bytes())
	expectedLength := pointLength + scalarLength*2
	if len(data) != expectedLength {
		return fmt.Errorf("invalid byte sequence")
	}
	a, err := sig.a.FromAffineCompressed(data[:pointLength])
	if err != nil {
		return err
	}
	e, err := sig.e.SetBytes(data[pointLength:(pointLength + scalarLength)])
	if err != nil {
		return err
	}
	s, err := sig.s.SetBytes(data[(pointLength + scalarLength):])
	if err != nil {
		return err
	}
	var ok bool
	sig.a, ok = a.(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}
	sig.e = e
	sig.s = s
	return nil
}

func (*Signature) Type() groupsig.GroupSignatureScheme {
	return groupsig.BBS
}

func (sig *Signature) Curve() (*curves.PairingCurve, error) {
	if curve := curves.GetPairingCurveByName(sig.a.CurveName()); curve != nil {
		return curve, nil
	}
	return nil, fmt.Errorf("invalid curve")
}

func (sig *Signature) Verify(publicKey groupsig.PublicKey, messages []curves.Scalar) error {
	pk, ok := publicKey.(*PublicKeyWithGenerators)
	if !ok {
		return fmt.Errorf("invalid public key")
	}
	return pk.PublicKey.Verify(sig, pk.Generators, messages)
}

func (*Signature) Unblind(blinder common.SignatureBlinding) (groupsig.Signature, error) {
	return nil, fmt.Errorf("unsupported")
}
