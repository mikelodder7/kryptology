//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"fmt"
	"math/big"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core"
)

// EncryptionKey encrypts a message to a ciphertext from which
// zero-knowledge proofs can be derived
// as described in section 3.2 in <https://shoup.net/papers/verenc.pdf>.
// n, g are stored in the `PaillierGroup` struct.
type EncryptionKey struct {
	y1     []*big.Int
	y2, y3 *big.Int
	group  *PaillierGroup
}

func NewKeys(numMsgs uint, group *PaillierGroup) (*EncryptionKey, *DecryptionKey, error) {
	if numMsgs < 1 {
		return nil, nil, fmt.Errorf("number of messages should be greater than 0")
	}

	x1 := make([]*big.Int, numMsgs)
	y1 := make([]*big.Int, numMsgs)
	for i := range x1 {
		x, err := core.Rand(group.n2d4)
		if err != nil {
			return nil, nil, err
		}
		x1[i] = x
		y1[i] = group.Gexp(x)
	}
	x2, err := core.Rand(group.n2d4)
	if err != nil {
		return nil, nil, err
	}
	y2 := group.Gexp(x2)
	x3, err := core.Rand(group.n2d4)
	if err != nil {
		return nil, nil, err
	}
	y3 := group.Gexp(x3)
	dk := &DecryptionKey{
		x1, x2, x3, group,
	}
	ek := &EncryptionKey{
		y1, y2, y3, group,
	}
	return ek, dk, nil
}

// MarshalBinary serializes a key to bytes.
func (ek EncryptionKey) MarshalBinary() ([]byte, error) {
	return marshalData(ek.group, ek.y3, ek.y2, ek.y1)
}

// UnmarshalBinary deserializes a key from bytes.
func (ek *EncryptionKey) UnmarshalBinary(data []byte) error {
	group, y3, y2, y1, err := unmarshalData(data)
	if err != nil {
		return errors.WithStack(err)
	}
	ek.group = group
	ek.y3 = y3
	ek.y2 = y2
	ek.y1 = y1
	return nil
}

// Encrypt multiple messages as described in <https://shoup.net/papers/verenc.pdf>
// `domain` represents a domain separation tag or nonce.
func (ek EncryptionKey) Encrypt(domain []byte, msgs []*big.Int) (*CipherText, error) {
	if len(msgs) > len(ek.y1) {
		return nil, fmt.Errorf("number of messages %d is more than supported by this key %d", len(msgs), len(ek.y1))
	}
	for i, m := range msgs {
		if m == nil || m.Cmp(ek.group.n) == 1 {
			return nil, fmt.Errorf("message %d is not valid", i)
		}
	}
	r, err := ek.group.RandForEncrypt()
	if err != nil {
		return nil, err
	}
	return ek.encryptWithR(domain, msgs, r)
}

func (ek EncryptionKey) encryptWithR(domain []byte, msgs []*big.Int, r *big.Int) (*CipherText, error) {
	u := ek.computeU(r)
	e := ek.computeE(msgs, r)

	hs, err := ek.group.Hash(u, e, domain)
	if err != nil {
		return nil, err
	}
	v := ek.computeV(r, hs, true)
	return &CipherText{u, v, e}, nil
}

func (ek EncryptionKey) computeE(msgs []*big.Int, r *big.Int) []*big.Int {
	e := make([]*big.Int, len(msgs))
	for i, m := range msgs {
		y := ek.group.Exp(ek.y1[i], r)
		hM := ek.group.Hexp(m)
		e[i] = ek.group.Mul(y, hM)
	}
	return e
}

func (ek EncryptionKey) computeU(r *big.Int) *big.Int {
	return ek.group.Gexp(r)
}

// computeV computes the `v` value during encryption
// abs is present for code reuse as during the proof of encryption
// in the commitment step absolute value is not taken.
func (ek EncryptionKey) computeV(r, hash *big.Int, abs bool) *big.Int {
	// y3 ^ h(u, e, L)
	y3hs := ek.group.Exp(ek.y3, hash)

	// y2 * (y3^h(u, e, L))
	y2y3hs := ek.group.Mul(ek.y2, y3hs)

	// (y2y3^h(u, e, L))^r
	y2y3hsr := ek.group.Exp(y2y3hs, r)
	if abs {
		return ek.group.Abs(y2y3hsr)
	} else {
		return y2y3hsr
	}
}
