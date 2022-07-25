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

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
)

// DecryptionKey decrypts verifiable ciphertext
// as described in section 3.2 in <https://shoup.net/papers/verenc.pdf>
type DecryptionKey struct {
	x1     []*big.Int
	x2, x3 *big.Int
	group  *PaillierGroup
}

// EncryptionKey returns the corresponding encryption key for this decryption key.
func (dk DecryptionKey) EncryptionKey() *EncryptionKey {
	y2 := dk.group.Gexp(dk.x2)
	y3 := dk.group.Gexp(dk.x3)
	y1 := make([]*big.Int, len(dk.x1))
	for i, x := range dk.x1 {
		y1[i] = dk.group.Gexp(x)
	}
	return &EncryptionKey{
		y1, y2, y3, dk.group,
	}
}

// MarshalBinary serializes a key to bytes.
func (dk DecryptionKey) MarshalBinary() ([]byte, error) {
	return marshalData(dk.group, dk.x3, dk.x2, dk.x1)
}

// UnmarshalBinary deserializes a key from bytes.
func (dk *DecryptionKey) UnmarshalBinary(data []byte) error {
	group, x3, x2, x1, err := unmarshalData(data)
	if err != nil {
		return errors.WithStack(err)
	}
	dk.group = group
	dk.x3 = x3
	dk.x2 = x2
	dk.x1 = x1
	return nil
}

// Decrypt as described in section 3.2 in <https://shoup.net/papers/verenc.pdf>
func (dk DecryptionKey) Decrypt(domain []byte, cipherText *CipherText) ([]*big.Int, error) {
	if cipherText == nil {
		return nil, internal.ErrNilArguments
	}
	if cipherText.v == nil || cipherText.u == nil || cipherText.e == nil {
		return nil, internal.ErrNilArguments
	}
	if len(cipherText.e) > len(dk.x1) {
		return nil, fmt.Errorf("number of messages %d is more than supported by this key %d", len(cipherText.e), len(dk.x1))
	}
	if cipherText.u.Cmp(core.Zero) == 0 || cipherText.v.Cmp(core.Zero) == 0 {
		return nil, internal.ErrZeroValue
	}
	for _, e := range cipherText.e {
		if e.Cmp(core.Zero) == 0 {
			return nil, internal.ErrZeroValue
		}
	}

	// Check if abs(v) == v
	if cipherText.v.Cmp(dk.group.Abs(cipherText.v)) != 0 {
		return nil, fmt.Errorf("absolute check failed")
	}

	// h(u, e, L)
	hs, err := dk.group.Hash(cipherText.u, cipherText.e, domain)
	if err != nil {
		return nil, err
	}

	// h(u, e, L) * x3
	hsX3 := new(big.Int).Mul(hs, dk.x3)
	twoHsX3PlusX2 := new(big.Int).Add(hsX3, dk.x2)
	// 2 * (h(u, e, L) * x3 + x2)
	twoHsX3PlusX2.Lsh(twoHsX3PlusX2, 1)

	uSqr := dk.group.Exp(cipherText.u, twoHsX3PlusX2)
	vSqr := dk.group.Exp(cipherText.v, big.NewInt(2))

	if uSqr.Cmp(vSqr) != 0 {
		return nil, fmt.Errorf("u^2 != v^2")
	}

	msgs := make([]*big.Int, len(cipherText.e))
	for i, ee := range cipherText.e {
		// u^{x_1}
		uX1 := dk.group.Exp(cipherText.u, dk.x1[i])
		// 1/u^{x_1}
		uX1Inv := dk.group.Inv(uX1)
		// e/u^{x_1}
		eUX1Inv := dk.group.Mul(ee, uX1Inv)

		// m_hat = (e/u^{x_1})^2t
		mHat := dk.group.Exp(eUX1Inv, dk.group.twoInvTwo)
		test := new(big.Int).Mod(mHat, dk.group.n)
		if test.Cmp(big.NewInt(1)) != 0 {
			return nil, fmt.Errorf("decryption failed for message %d", i)
		}

		m := new(big.Int).Mod(mHat, dk.group.n2)
		m.Sub(m, big.NewInt(1))
		m.Div(m, dk.group.n)
		msgs[i] = m
	}

	return msgs, nil
}

func marshalData(pGroup *PaillierGroup, a3, a2 *big.Int, a1 []*big.Int) ([]byte, error) {
	group, err := pGroup.MarshalBinary()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	x3 := a3.Bytes()
	x2 := a2.Bytes()
	x1 := make([][]byte, len(a1))
	for i, y := range a1 {
		x1[i] = y.Bytes()
	}
	b := core.NewByteSerializer(uint(len(group) + len(x3) + len(x2) + len(x1)*len(x2)))
	if _, err = b.WriteBytes(group); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = b.WriteBytes(x3); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = b.WriteBytes(x2); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = b.WriteByteArray(x1); err != nil {
		return nil, errors.WithStack(err)
	}
	return b.Bytes(), nil
}

func unmarshalData(data []byte) (*PaillierGroup, *big.Int, *big.Int, []*big.Int, error) {
	b := core.NewByteDeserializer(data)
	groupBytes, err := b.ReadBytes()
	if err != nil {
		return nil, nil, nil, nil, errors.WithStack(err)
	}
	a3Bytes, err := b.ReadBytes()
	if err != nil {
		return nil, nil, nil, nil, errors.WithStack(err)
	}
	a2Bytes, err := b.ReadBytes()
	if err != nil {
		return nil, nil, nil, nil, errors.WithStack(err)
	}
	a1Bytes, err := b.ReadByteArray()
	if err != nil {
		return nil, nil, nil, nil, errors.WithStack(err)
	}

	group := new(PaillierGroup)
	if err = group.UnmarshalBinary(groupBytes); err != nil {
		return nil, nil, nil, nil, errors.WithStack(err)
	}
	a2 := new(big.Int).SetBytes(a2Bytes)
	a3 := new(big.Int).SetBytes(a3Bytes)
	a1 := make([]*big.Int, len(a1Bytes))
	for i, d := range a1Bytes {
		a1[i] = new(big.Int).SetBytes(d)
	}
	return group, a3, a2, a1, nil
}
