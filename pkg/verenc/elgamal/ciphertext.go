//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// CipherText represents verifiably encrypted ciphertext
// using El-Gamal encryption.
type CipherText struct {
	C1, C2      curves.Point
	Nonce       []byte
	Aead        []byte
	MsgIsHashed bool
}

// HomomorphicCipherText represents encrypted ciphertexts
// that have been added together. The result when decrypted
// does not include the AEAD encrypted ciphertexts since
// these are not homomorphic. This is solely for checking
// results or ignoring the AEAD ciphertext.
type HomomorphicCipherText struct {
	C1, C2 curves.Point
}

func (c *CipherText) MarshalBinary() ([]byte, error) {
	c1, err := curves.PointMarshalBinary(c.C1)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	c2, err := curves.PointMarshalBinary(c.C2)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	b := core.NewByteSerializer(uint(1 + len(c.Nonce) + len(c.Aead) + len(c1) + len(c2)))
	if _, err = b.WriteBytes(c1); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = b.WriteBytes(c2); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = b.WriteBytes(c.Nonce); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = b.WriteBytes(c.Aead); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = b.WriteBool(c.MsgIsHashed); err != nil {
		return nil, errors.WithStack(err)
	}

	return b.Bytes(), nil
}

func (c *CipherText) UnmarshalBinary(data []byte) error {
	b := core.NewByteDeserializer(data)
	c1Bytes, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	c2Bytes, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	nonce, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	aead, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	msgIsHashed, err := b.ReadBool()
	if err != nil {
		return errors.WithStack(err)
	}
	c1, err := curves.PointUnmarshalBinary(c1Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	c2, err := curves.PointUnmarshalBinary(c2Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	c.C1 = c1
	c.C2 = c2
	c.Aead = make([]byte, len(aead))
	copy(c.Aead, aead)
	c.Nonce = make([]byte, len(nonce))
	copy(c.Nonce, nonce)
	c.MsgIsHashed = msgIsHashed

	return nil
}

// ToHomomorphicCipherText returns the El-Gamal points that can be
// homomorphically multiplied.
func (c *CipherText) ToHomomorphicCipherText() *HomomorphicCipherText {
	return &HomomorphicCipherText{
		C1: c.C1,
		C2: c.C2,
	}
}

// Add combines two ciphertexts multiplicatively homomorphic.
func (c *HomomorphicCipherText) Add(rhs *HomomorphicCipherText) *HomomorphicCipherText {
	return &HomomorphicCipherText{
		C1: c.C1.Add(rhs.C1),
		C2: c.C2.Add(rhs.C2),
	}
}

// Decrypt returns the C2 - C1.
func (c *HomomorphicCipherText) Decrypt(dk *DecryptionKey) (curves.Point, error) {
	if dk == nil {
		return nil, internal.ErrNilArguments
	}
	return c.C2.Sub(c.C1.Mul(dk.x)), nil
}

func (c *HomomorphicCipherText) MarshalBinary() ([]byte, error) {
	c1, err := curves.PointMarshalBinary(c.C1)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	c2, err := curves.PointMarshalBinary(c.C2)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	b := core.NewByteSerializer(uint(len(c1) + len(c2)))
	_, err = b.WriteBytes(c1)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	_, err = b.WriteBytes(c2)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return b.Bytes(), nil
}

func (c *HomomorphicCipherText) UnmarshalBinary(in []byte) error {
	b := core.NewByteDeserializer(in)
	c1Bytes, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	c2Bytes, err := b.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	c1, err := curves.PointUnmarshalBinary(c1Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	c2, err := curves.PointUnmarshalBinary(c2Bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	c.C1 = c1
	c.C2 = c2
	return nil
}
