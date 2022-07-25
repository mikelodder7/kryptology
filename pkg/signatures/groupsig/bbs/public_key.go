//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"errors"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// PublicKey is a BBS+ verification key.
type PublicKey struct {
	value curves.PairingPoint
}

func (pk *PublicKey) Init(curve *curves.PairingCurve) *PublicKey {
	pk.value = curve.NewG2IdentityPoint()
	return pk
}

func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return pk.value.ToAffineCompressed(), nil
}

func (pk *PublicKey) UnmarshalBinary(in []byte) error {
	value, err := pk.value.FromAffineCompressed(in)
	if err != nil {
		return err
	}
	var ok bool
	pk.value, ok = value.(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}
	return nil
}

// Verify checks a signature where all messages are known to the verifier.
func (pk PublicKey) Verify(signature *Signature, generators *MessageGenerators, msgs []curves.Scalar) error {
	if generators.length < len(msgs) {
		return fmt.Errorf("not enough message generators")
	}
	if len(msgs) < 1 {
		return fmt.Errorf("invalid messages")
	}
	// Identity Point will always return true which is not what we want
	if pk.value.IsIdentity() {
		return fmt.Errorf("invalid public key")
	}
	if signature.a.IsIdentity() {
		return fmt.Errorf("invalid signature")
	}
	a, ok := pk.value.Generator().Mul(signature.e).Add(pk.value).(curves.PairingPoint)
	if !ok {
		return fmt.Errorf("not a valid point")
	}
	b, ok := computeB(signature.s, msgs, generators).Neg().(curves.PairingPoint)
	if !ok {
		return fmt.Errorf("not a valid point")
	}

	pairingPoint, ok := pk.value.Generator().(curves.PairingPoint)
	if !ok {
		return fmt.Errorf("not a valid conversion")
	}
	res := a.MultiPairing(signature.a, a, b, pairingPoint)
	if !res.IsOne() {
		return fmt.Errorf("invalid result")
	}

	return nil
}

type PublicKeyWithGenerators struct {
	PublicKey  *PublicKey
	Generators *MessageGenerators
}

func (*PublicKeyWithGenerators) Type() groupsig.GroupSignatureScheme {
	return groupsig.BBS
}

func (pk *PublicKeyWithGenerators) Curve() (*curves.PairingCurve, error) {
	if curve := curves.GetPairingCurveByName(pk.PublicKey.value.CurveName()); curve != nil {
		return curve, nil
	}
	return nil, fmt.Errorf("invalid curve")
}

func (pk *PublicKeyWithGenerators) MessageCount() int {
	return pk.Generators.length
}
