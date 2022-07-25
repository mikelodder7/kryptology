//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
)

// Signature is a Mina compatible signature either for payment or delegation.
type Signature struct {
	R, S *native.Field
}

func (sig Signature) MarshalBinary() ([]byte, error) {
	var buf [64]byte
	rx := sig.R.Bytes()
	s := sig.S.Bytes()
	copy(buf[:32], rx[:])
	copy(buf[32:], s[:])
	return buf[:], nil
}

func (sig *Signature) UnmarshalBinary(input []byte) error {
	if len(input) != 64 {
		return fmt.Errorf("invalid byte sequence")
	}
	t := byte(0)
	for _, b := range input {
		t |= b
	}
	if t == 0 {
		return fmt.Errorf("invalid signature")
	}
	var buf [32]byte
	copy(buf[:], input[:32])
	rx, err := fp.PastaFpNew().SetBytes(&buf)
	if err != nil {
		return err
	}
	copy(buf[:], input[32:])
	s, err := fq.PastaFqNew().SetBytes(&buf)
	if err != nil {
		return err
	}
	sig.R = rx
	sig.S = s
	return nil
}
