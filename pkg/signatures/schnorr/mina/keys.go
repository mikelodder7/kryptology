//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/blake2b"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
)

const (
	version                  = 0xcb
	nonZeroCurvePointVersion = 0x01
	isCompressed             = 0x01
)

// PublicKey is the verification key.
type PublicKey struct {
	value *curves.PointPallas
}

// GenerateAddress converts the public key to an address.
func (pk PublicKey) GenerateAddress() string {
	var payload [40]byte
	payload[0] = version
	payload[1] = nonZeroCurvePointVersion
	payload[2] = isCompressed

	buffer := pk.value.ToAffineUncompressed()
	copy(payload[3:35], buffer[:32])
	payload[35] = buffer[32] & 1
	hash1 := sha256.Sum256(payload[:36])
	hash2 := sha256.Sum256(hash1[:])
	copy(payload[36:40], hash2[:4])
	return base58.Encode(payload[:])
}

// ParseAddress converts a given string into a public key returning an error on failure.
func (pk *PublicKey) ParseAddress(b58 string) error {
	buffer := base58.Decode(b58)
	if len(buffer) != 40 {
		return fmt.Errorf("invalid byte sequence")
	}
	if buffer[0] != version {
		return fmt.Errorf("invalid version")
	}
	if buffer[1] != nonZeroCurvePointVersion {
		return fmt.Errorf("invalid non-zero curve point version")
	}
	if buffer[2] != isCompressed {
		return fmt.Errorf("invalid compressed flag")
	}
	hash1 := sha256.Sum256(buffer[:36])
	hash2 := sha256.Sum256(hash1[:])
	if subtle.ConstantTimeCompare(hash2[:4], buffer[36:40]) != 1 {
		return fmt.Errorf("invalid checksum")
	}
	x := buffer[3:35]
	x[31] |= buffer[35] << 7
	value := new(curves.PointPallas)
	value.EllipticPoint = pasta.PointNew()
	pt, err := value.FromAffineCompressed(x)
	if err != nil {
		return err
	}
	pk.value, _ = pt.(*curves.PointPallas)
	return nil
}

func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return pk.value.ToAffineCompressed(), nil
}

func (pk *PublicKey) UnmarshalBinary(input []byte) error {
	pt := new(curves.PointPallas)
	pt.EllipticPoint = pasta.PointNew()
	t, err := pt.FromAffineCompressed(input)
	if err != nil {
		return err
	}
	pt, _ = t.(*curves.PointPallas)
	pk.value = pt
	return nil
}

func (pk *PublicKey) SetPointPallas(pallas *curves.PointPallas) {
	pk.value = new(curves.PointPallas)
	pk.value.EllipticPoint = pasta.PointNew().Set(pallas.EllipticPoint)
}

// SecretKey is the signing key.
type SecretKey struct {
	value *curves.ScalarPallas
}

// GetPublicKey returns the corresponding verification.
func (sk SecretKey) GetPublicKey() *PublicKey {
	pk := pasta.PointNew().Generator()
	pk.Mul(pk, sk.value.Value)
	value := new(curves.PointPallas)
	value.EllipticPoint = pk
	return &PublicKey{value}
}

func (sk SecretKey) MarshalBinary() ([]byte, error) {
	t := sk.value.Bytes()
	return t, nil
}

func (sk *SecretKey) UnmarshalBinary(input []byte) error {
	if len(input) != 32 {
		return fmt.Errorf("invalid byte sequence")
	}
	var buf [32]byte
	copy(buf[:], input)
	v, err := fq.PastaFqNew().SetBytes(&buf)
	if err != nil {
		return err
	}

	sk.value = new(curves.ScalarPallas)
	sk.value.Value = v
	return nil
}

func (sk *SecretKey) SetField(fqObject *native.Field) {
	sk.value = new(curves.ScalarPallas)
	sk.value.Value = fqObject
}

// NewKeys creates a new keypair using a CSPRNG.
func NewKeys() (*PublicKey, *SecretKey, error) {
	return NewKeysFromReader(crand.Reader)
}

// NewKeysFromReader creates a new keypair using the specified reader.
func NewKeysFromReader(reader io.Reader) (*PublicKey, *SecretKey, error) {
	t := new(curves.ScalarPallas).Random(reader)
	sc, ok := t.(*curves.ScalarPallas)
	if !ok || t.IsZero() {
		return nil, nil, fmt.Errorf("invalid key")
	}
	sk := sc.Value
	pk := pasta.PointNew().Generator()
	pk.Mul(pk, sk)
	if pk.IsIdentity() {
		return nil, nil, fmt.Errorf("invalid key")
	}

	pk.ToAffine(pk)
	valuePk := new(curves.PointPallas)
	valuePk.EllipticPoint = pk
	return &PublicKey{valuePk}, &SecretKey{sc}, nil
}

// SignTransaction generates a signature over the specified txn and network id
// See https://github.com/MinaProtocol/c-reference-signer/blob/master/crypto.c#L1020
func (sk *SecretKey) SignTransaction(transaction *Transaction) (*Signature, error) {
	input := new(roinput).Init(3, 75)
	transaction.addRoInput(input)
	return sk.finishSchnorrSign(input, transaction.NetworkId)
}

// SignMessage signs a _string_. this is somewhat non-standard; we do it by just adding bytes to the roinput.
// See https://github.com/MinaProtocol/c-reference-signer/blob/master/crypto.c#L1020
func (sk *SecretKey) SignMessage(message string) (*Signature, error) {
	input := new(roinput).Init(0, len(message))
	input.AddBytes([]byte(message))
	return sk.finishSchnorrSign(input, MainNet)
}

func (sk *SecretKey) finishSchnorrSign(input *roinput, networkId NetworkType) (*Signature, error) {
	if sk.value.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}
	pk := sk.GetPublicKey()
	k := sk.msgDerive(input, pk, networkId)
	if k.IsZero() == 1 {
		return nil, fmt.Errorf("invalid nonce generated")
	}
	// r = k*G
	r := pasta.PointNew().Generator()
	r.Mul(r, k)
	r.ToAffine(r)

	if r.Y.Bytes()[0]&1 == 1 {
		k.Neg(k)
	}
	rx := r.X
	e := msgHash(pk, rx, input, ThreeW, networkId)

	// S = k + e*sk
	e.Mul(e, sk.value.Value)
	s := fq.PastaFqNew().Add(k, e)
	if rx.IsZero()|s.IsZero() == 1 {
		return nil, fmt.Errorf("invalid signature")
	}
	return &Signature{
		R: rx,
		S: s,
	}, nil
}

// VerifyTransaction checks if the signature is over the given transaction using this public key.
func (pk *PublicKey) VerifyTransaction(sig *Signature, transaction *Transaction) error {
	input := new(roinput).Init(3, 75)
	transaction.addRoInput(input)
	return pk.finishSchnorrVerify(sig, input, transaction.NetworkId)
}

// VerifyMessage checks if the claimed signature on a _string_ is valid. this is nonstandard; see above.
func (pk *PublicKey) VerifyMessage(sig *Signature, message string) error {
	input := new(roinput).Init(0, len(message))
	input.AddBytes([]byte(message))
	return pk.finishSchnorrVerify(sig, input, MainNet)
}

func (pk *PublicKey) finishSchnorrVerify(sig *Signature, input *roinput, networkId NetworkType) error {
	if pk.value.IsIdentity() {
		return fmt.Errorf("invalid public key")
	}
	if sig.R.IsZero()|sig.S.IsZero() == 1 {
		return fmt.Errorf("invalid signature")
	}
	e := msgHash(pk, sig.R, input, ThreeW, networkId)
	sg := pasta.PointNew().Generator()
	sg.Mul(sg, sig.S)

	epk := pasta.PointNew().Set(pk.value.EllipticPoint)
	epk.Mul(epk, e)
	epk.Neg(epk)

	r := pasta.PointNew().Add(sg, epk)
	r.ToAffine(r)
	if r.Y.Bytes()[0]&1 == 0 && r.X.Equal(sig.R) == 1 {
		return nil
	} else {
		return fmt.Errorf("signature verification failed")
	}
}

func msgHash(pk *PublicKey, rx *native.Field, input *roinput, hashType Permutation, networkId NetworkType) *native.Field {
	ep := pasta.PointNew().ToAffine(pk.value.EllipticPoint)
	input.AddFp(ep.X)
	input.AddFp(ep.Y)
	input.AddFp(rx)

	ctx := new(Context).Init(hashType, networkId)
	fields := input.Fields()
	ctx.Update(fields)
	return ctx.Digest()
}

func (sk SecretKey) msgDerive(msg *roinput, pk *PublicKey, networkId NetworkType) *native.Field {
	input := msg.Clone()
	input.AddFp(pk.value.X())
	input.AddFp(pk.value.Y())
	input.AddFq(sk.value.Value)
	input.AddBytes([]byte{byte(networkId)})
	inputBytes := input.Bytes()

	h, _ := blake2b.New(32, []byte{})
	_, _ = h.Write(inputBytes)
	hash := h.Sum(nil)

	// Clear top two bits
	hash[31] &= 0x3F
	tmp := [4]uint64{
		binary.LittleEndian.Uint64(hash[:8]),
		binary.LittleEndian.Uint64(hash[8:16]),
		binary.LittleEndian.Uint64(hash[16:24]),
		binary.LittleEndian.Uint64(hash[24:32]),
	}
	return fq.PastaFqNew().SetLimbs(&tmp)
}
