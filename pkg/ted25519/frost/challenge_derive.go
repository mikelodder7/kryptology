//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"crypto/sha512"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/schnorr/mina"
)

type ChallengeDeriver func(msg []byte, pubKey, r curves.Point) (curves.Scalar, error)

func DeriveChallenge(msg []byte, pubKey, r curves.Point) (curves.Scalar, error) {
	h := sha512.New()
	_, _ = h.Write(r.ToAffineCompressed())
	_, _ = h.Write(pubKey.ToAffineCompressed())
	_, _ = h.Write(msg)
	return pubKey.Scalar().SetBytesWide(h.Sum(nil))
}

func DeriveMinaChallenge(msg []byte, pubKey, r curves.Point) (curves.Scalar, error) {
	handler := &mina.TSchnorrHandler{}
	scalar, err := handler.DeriveChallenge(msg, pubKey, r)
	if err != nil {
		return nil, err
	}
	return scalar, nil
}
