//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// BlindSignature is a BBS+ blind signature
// structurally identical to `Signature` but
// is used to help avoid misuse and confusion.
//
// 1 or more message have been hidden by the
// potential signature holder so the signer
// only knows a subset of the messages to be signed.
type BlindSignature struct {
	signature *Signature
}

// // Init creates an empty signature to a specific curve
// // which should be followed by UnmarshalBinary.
func (sig *BlindSignature) Init(curve *curves.PairingCurve) *BlindSignature {
	internalSignature := &Signature{}
	sig.signature = internalSignature.Init(curve)
	return sig
}

func (sig BlindSignature) MarshalBinary() ([]byte, error) {
	out, err := sig.signature.MarshalBinary()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return out, nil
}

func (sig *BlindSignature) UnmarshalBinary(data []byte) error {
	err := sig.signature.UnmarshalBinary(data)
	return err
}

func (sig BlindSignature) ToUnblinded(blinder common.SignatureBlinding) *Signature {
	return &Signature{
		a: sig.signature.a,
		e: sig.signature.e,
		s: sig.signature.s.Add(blinder),
	}
}

func (*BlindSignature) Type() groupsig.GroupSignatureScheme {
	return groupsig.BBS
}

func (sig *BlindSignature) Curve() (*curves.PairingCurve, error) {
	if curve := curves.GetPairingCurveByName(sig.signature.a.CurveName()); curve != nil {
		return curve, nil
	}
	return nil, fmt.Errorf("invalid curve")
}

func (*BlindSignature) Verify(publicKey groupsig.PublicKey, messages []curves.Scalar) error {
	return fmt.Errorf("cannot verify a blind signature")
}

func (sig *BlindSignature) Unblind(blinder common.SignatureBlinding) (groupsig.Signature, error) {
	return sig.ToUnblinded(blinder), nil
}
