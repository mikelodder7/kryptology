//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"math/big"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core"
)

// CipherText represents verifiably encrypted ciphertext
// as described in section 3.2 in <https://shoup.net/papers/verenc.pdf>.
type CipherText struct {
	u, v *big.Int
	e    []*big.Int
}

func (c CipherText) MarshalBinary() ([]byte, error) {
	u := c.u.Bytes()
	v := c.v.Bytes()
	eA := make([][]byte, len(c.e))
	for i, e := range c.e {
		eA[i] = e.Bytes()
	}
	b := core.NewByteSerializer(uint(len(u) + len(v) + len(eA)*len(u)))
	if _, err := b.WriteBytes(u); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err := b.WriteBytes(v); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err := b.WriteByteArray(eA); err != nil {
		return nil, errors.WithStack(err)
	}
	return b.Bytes(), nil
}

func (c *CipherText) UnmarshalBinary(data []byte) error {
	b := core.NewByteDeserializer(data)
	uBytes, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	vBytes, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	eABytes, err := b.ReadByteArray()
	if err != nil {
		return errors.WithStack(err)
	}

	c.u = new(big.Int).SetBytes(uBytes)
	c.v = new(big.Int).SetBytes(vBytes)
	c.e = make([]*big.Int, len(eABytes))
	for i, e := range eABytes {
		c.e[i] = new(big.Int).SetBytes(e)
	}
	return nil
}
