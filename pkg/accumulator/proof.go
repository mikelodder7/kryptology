//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"

	"github.com/gtank/merlin"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// ProofParams contains four distinct public generators of G1 - X, Y, Z.
type ProofParams struct {
	x, y, z curves.Point
}

// New samples X, Y, Z, K.
func (p *ProofParams) New(curve *curves.PairingCurve, pk *PublicKey, entropy []byte) (*ProofParams, error) {
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	prefix := bytes.Repeat([]byte{0xFF}, 32)
	data := prefix
	data = append(data, entropy...)
	data = append(data, pkBytes...)
	p.z = curve.Scalar.Point().Hash(data)

	data[0] = 0xFE
	p.y = curve.Scalar.Point().Hash(data)

	data[0] = 0xFD
	p.x = curve.Scalar.Point().Hash(data)

	return p, nil
}

// MarshalBinary converts ProofParams to bytes.
func (p *ProofParams) MarshalBinary() ([]byte, error) {
	if p.x == nil || p.y == nil || p.z == nil {
		return nil, fmt.Errorf("some value x, y, or z is nil")
	}
	x, err := curves.PointMarshalBinary(p.x)
	if err != nil {
		return nil, err
	}
	y, err := curves.PointMarshalBinary(p.y)
	if err != nil {
		return nil, err
	}
	z, err := curves.PointMarshalBinary(p.z)
	if err != nil {
		return nil, err
	}
	b := core.NewByteSerializer(uint(len(x) + len(y) + len(z)))
	if _, err = b.WriteBytes(x); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(y); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(z); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalBinary converts bytes to ProofParams.
func (p *ProofParams) UnmarshalBinary(data []byte) error {
	if data == nil {
		return fmt.Errorf("expected non-zero byte sequence")
	}
	b := core.NewByteDeserializer(data)
	xBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	yBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	zBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	x, err := curves.PointUnmarshalBinary(xBytes)
	if err != nil {
		return err
	}
	y, err := curves.PointUnmarshalBinary(yBytes)
	if err != nil {
		return err
	}
	z, err := curves.PointUnmarshalBinary(zBytes)
	if err != nil {
		return err
	}
	p.x = x
	p.y = y
	p.z = z
	return nil
}

// MembershipProofCommitting contains value computed in Proof of knowledge and
// Blinding phases as described in section 7 of https://eprint.iacr.org/2020/777.pdf
type MembershipProofCommitting struct {
	eC             curves.Point
	tSigma         curves.Point
	tRho           curves.Point
	deltaSigma     curves.Scalar
	deltaRho       curves.Scalar
	blindingFactor curves.Scalar
	rSigma         curves.Scalar
	rRho           curves.Scalar
	rDeltaSigma    curves.Scalar
	rDeltaRho      curves.Scalar
	sigma          curves.Scalar
	rho            curves.Scalar
	capRSigma      curves.Point
	capRRho        curves.Point
	capRDeltaSigma curves.Point
	capRDeltaRho   curves.Point
	capRE          curves.Scalar
	accumulator    curves.Point
	witnessValue   curves.Scalar
	xG1            curves.Point
	yG1            curves.Point
	zG1            curves.Point
}

// New initiates values of MembershipProofCommitting.
func (*MembershipProofCommitting) New(
	witness *MembershipWitness,
	acc *Accumulator,
	pp *ProofParams,
	pk *PublicKey,
	blindingFactor curves.Scalar,
) (*MembershipProofCommitting, error) {
	// Randomly select σ, ρ
	sigma := witness.y.Random(crand.Reader)
	rho := witness.y.Random(crand.Reader)

	// E_C = C + (σ + ρ)Z
	t := sigma
	t = t.Add(rho)
	eC := pp.z
	eC = eC.Mul(t)
	eC = eC.Add(witness.c)

	// T_σ = σX
	tSigma := pp.x
	tSigma = tSigma.Mul(sigma)

	// T_ρ = ρY
	tRho := pp.y
	tRho = tRho.Mul(rho)

	// δ_σ = yσ
	deltaSigma := witness.y
	deltaSigma = deltaSigma.Mul(sigma)

	// δ_ρ = yρ
	deltaRho := witness.y
	deltaRho = deltaRho.Mul(rho)

	// Randomly pick r_σ,r_ρ,r_δσ,r_δρ
	var rY curves.Scalar
	if blindingFactor == nil {
		rY = witness.y.Random(crand.Reader)
	} else {
		rY = blindingFactor.Clone()
	}
	rSigma := witness.y.Random(crand.Reader)
	rRho := witness.y.Random(crand.Reader)
	rDeltaSigma := witness.y.Random(crand.Reader)
	rDeltaRho := witness.y.Random(crand.Reader)

	// R_σ = r_σ X
	capRSigma := pp.x
	capRSigma = capRSigma.Mul(rSigma)

	// R_ρ = ρY
	capRRho := pp.y
	capRRho = capRRho.Mul(rRho)

	// R_δσ = r_y T_σ - r_δσ X
	negX := pp.x
	negX = negX.Neg()
	capRDeltaSigma := tSigma.Mul(rY)
	capRDeltaSigma = capRDeltaSigma.Add(negX.Mul(rDeltaSigma))

	// R_δρ = r_y T_ρ - r_δρ Y
	negY := pp.y
	negY = negY.Neg()
	capRDeltaRho := tRho.Mul(rY)
	capRDeltaRho = capRDeltaRho.Add(negY.Mul(rDeltaRho))

	// P~
	g2 := pk.value.Generator()

	// -r_δσ - r_δρ
	exp := rDeltaSigma
	exp = exp.Add(rDeltaRho)
	exp = exp.Neg()

	// -r_σ - r_ρ
	exp2 := rSigma
	exp2 = exp2.Add(rRho)
	exp2 = exp2.Neg()

	// rY * eC
	rYeC := eC.Mul(rY)

	// (-r_δσ - r_δρ)*Z
	expZ := pp.z.Mul(exp)

	// (-r_σ - r_ρ)*Z
	exp2Z := pp.z.Mul(exp2)

	// Prepare
	rYeCPrep, ok := rYeC.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	g2Prep, ok := g2.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	expZPrep, ok := expZ.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	exp2ZPrep, ok := exp2Z.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	pkPrep := pk.value

	// Pairing
	capRE := g2Prep.MultiPairing(rYeCPrep, g2Prep, expZPrep, g2Prep, exp2ZPrep, pkPrep)

	return &MembershipProofCommitting{
		eC,
		tSigma,
		tRho,
		deltaSigma,
		deltaRho,
		rY,
		rSigma,
		rRho,
		rDeltaSigma,
		rDeltaRho,
		sigma,
		rho,
		capRSigma,
		capRRho,
		capRDeltaSigma,
		capRDeltaRho,
		capRE,
		acc.value,
		witness.y,
		pp.x,
		pp.y,
		pp.z,
	}, nil
}

// GetChallengeBytes returns bytes that need to be hashed for generating challenge.
// V || Ec || T_sigma || T_rho || R_E || R_sigma || R_rho || R_delta_sigma || R_delta_rho.
func (mpc *MembershipProofCommitting) WriteChallengeContributionToTranscript(transcript *merlin.Transcript) {
	writeChallengeContributionToTranscript(&[9][]byte{
		mpc.accumulator.ToAffineCompressed(),
		mpc.eC.ToAffineCompressed(),
		mpc.tSigma.ToAffineCompressed(),
		mpc.tRho.ToAffineCompressed(),
		mpc.capRE.Bytes(),
		mpc.capRSigma.ToAffineCompressed(),
		mpc.capRRho.ToAffineCompressed(),
		mpc.capRDeltaSigma.ToAffineCompressed(),
		mpc.capRDeltaRho.ToAffineCompressed(),
	}, transcript,
	)
}

// GenProof computes the s values for Fiat-Shamir and return the actual
// proof to be sent to the verifier given the challenge c.
func (mpc *MembershipProofCommitting) GenProof(c curves.Scalar) *MembershipProof {
	// s_y = r_y + c*y
	sY := schnorr(mpc.blindingFactor, mpc.witnessValue, c)
	// s_σ = r_σ + c*σ
	sSigma := schnorr(mpc.rSigma, mpc.sigma, c)
	// s_ρ = r_ρ + c*ρ
	sRho := schnorr(mpc.rRho, mpc.rho, c)
	// s_δσ = rδσ + c*δ_σ
	sDeltaSigma := schnorr(mpc.rDeltaSigma, mpc.deltaSigma, c)
	// s_δρ = rδρ + c*δ_ρ
	sDeltaRho := schnorr(mpc.rDeltaRho, mpc.deltaRho, c)

	return &MembershipProof{
		mpc.eC,
		mpc.tSigma,
		mpc.tRho,
		sSigma,
		sRho,
		sDeltaSigma,
		sDeltaRho,
		sY,
	}
}

func schnorr(r, v, challenge curves.Scalar) curves.Scalar {
	res := v
	res = res.Mul(challenge)
	res = res.Add(r)
	return res
}

// MembershipProof contains values in the proof to be verified.
type MembershipProof struct {
	eC          curves.Point
	tSigma      curves.Point
	tRho        curves.Point
	sSigma      curves.Scalar
	sRho        curves.Scalar
	sDeltaSigma curves.Scalar
	sDeltaRho   curves.Scalar
	sY          curves.Scalar
}

// Finalize computes values in the proof to be verified.
func (mp *MembershipProof) Finalize(acc *Accumulator, pp *ProofParams, pk *PublicKey, challenge curves.Scalar) (*MembershipProofFinal, error) {
	// R_σ = s_δ X + c T_σ
	negTSigma := mp.tSigma
	negTSigma = negTSigma.Neg()
	capRSigma := pp.x.Mul(mp.sSigma)
	capRSigma = capRSigma.Add(negTSigma.Mul(challenge))

	// R_ρ = s_ρ Y + c T_ρ
	negTRho := mp.tRho
	negTRho = negTRho.Neg()
	capRRho := pp.y.Mul(mp.sRho)
	capRRho = capRRho.Add(negTRho.Mul(challenge))

	// R_δσ =  s_y T_σ - s_δσ X
	negX := pp.x
	negX = negX.Neg()
	capRDeltaSigma := mp.tSigma.Mul(mp.sY)
	capRDeltaSigma = capRDeltaSigma.Add(negX.Mul(mp.sDeltaSigma))

	// R_δρ =  s_y T_ρ - s_δρ Y
	negY := pp.y
	negY = negY.Neg()
	capRDeltaRho := mp.tRho.Mul(mp.sY)
	capRDeltaRho = capRDeltaRho.Add(negY.Mul(mp.sDeltaRho))

	// tildeP
	g2 := pk.value.Generator()

	// Compute capRE, the pairing
	// E_c * s_y
	eCsY := mp.eC.Mul(mp.sY)

	// (-s_delta_sigma - s_delta_rho) * Z
	exp := mp.sDeltaSigma
	exp = exp.Add(mp.sDeltaRho)
	exp = exp.Neg()
	expZ := pp.z.Mul(exp)

	// (-c) * V
	exp = challenge.Neg()
	expV := acc.value.Mul(exp)

	// E_c * s_y + (-s_delta_sigma - s_delta_rho) * Z + (-c) * V
	lhs := eCsY.Add(expZ).Add(expV)

	// (-s_sigma - s_rho) * Z
	exp = mp.sSigma
	exp = exp.Add(mp.sRho)
	exp = exp.Neg()
	expZ2 := pp.z.Mul(exp)

	// E_c * c
	cEc := mp.eC.Mul(challenge)

	// (-s_sigma - s_rho) * Z + E_c * c
	rhs := cEc.Add(expZ2)

	// Prepare
	lhsPrep, ok := lhs.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	g2Prep, ok := g2.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	rhsPrep, ok := rhs.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	pkPrep := pk.value

	// capRE
	capRE := g2Prep.MultiPairing(lhsPrep, g2Prep, rhsPrep, pkPrep)

	return &MembershipProofFinal{
		acc.value,
		mp.eC,
		mp.tSigma,
		mp.tRho,
		capRE,
		capRSigma,
		capRRho,
		capRDeltaSigma,
		capRDeltaRho,
	}, nil
}

// MarshalBinary converts MembershipProof to bytes.
func (mp *MembershipProof) MarshalBinary() ([]byte, error) {
	ec, err := curves.PointMarshalBinary(mp.eC)
	if err != nil {
		return nil, err
	}
	tsigma, err := curves.PointMarshalBinary(mp.tSigma)
	if err != nil {
		return nil, err
	}
	trho, err := curves.PointMarshalBinary(mp.tRho)
	if err != nil {
		return nil, err
	}
	sSigma, err := curves.ScalarMarshalBinary(mp.sSigma)
	if err != nil {
		return nil, err
	}
	sRho, err := curves.ScalarMarshalBinary(mp.sRho)
	if err != nil {
		return nil, err
	}
	sDeltaSigma, err := curves.ScalarMarshalBinary(mp.sDeltaSigma)
	if err != nil {
		return nil, err
	}
	sDeltaRho, err := curves.ScalarMarshalBinary(mp.sDeltaRho)
	if err != nil {
		return nil, err
	}
	sY, err := curves.ScalarMarshalBinary(mp.sY)
	if err != nil {
		return nil, err
	}
	b := core.NewByteSerializer(uint(
		len(ec) + len(tsigma) + len(trho) +
			len(sSigma) + len(sRho) + len(sDeltaSigma) + len(sDeltaRho),
	))
	if _, err = b.WriteBytes(ec); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(tsigma); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(trho); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(sSigma); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(sRho); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(sDeltaSigma); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(sDeltaRho); err != nil {
		return nil, err
	}
	if _, err = b.WriteBytes(sY); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalBinary converts bytes to MembershipProof.
func (mp *MembershipProof) UnmarshalBinary(data []byte) error {
	if data == nil {
		return fmt.Errorf("expected non-zero byte sequence")
	}
	b := core.NewByteDeserializer(data)
	ecBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	tSigmaBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	tRhoBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	sSigmaBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	sRhoBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	sDeltaSigmaBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	sDeltaRhoBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	sYBytes, err := b.ReadBytes()
	if err != nil {
		return err
	}
	eC, err := curves.PointUnmarshalBinary(ecBytes)
	if err != nil {
		return err
	}
	tSigma, err := curves.PointUnmarshalBinary(tSigmaBytes)
	if err != nil {
		return err
	}
	tRho, err := curves.PointUnmarshalBinary(tRhoBytes)
	if err != nil {
		return err
	}
	sSigma, err := curves.ScalarUnmarshalBinary(sSigmaBytes)
	if err != nil {
		return err
	}
	sRho, err := curves.ScalarUnmarshalBinary(sRhoBytes)
	if err != nil {
		return err
	}
	sDeltaSigma, err := curves.ScalarUnmarshalBinary(sDeltaSigmaBytes)
	if err != nil {
		return err
	}
	sDeltaRho, err := curves.ScalarUnmarshalBinary(sDeltaRhoBytes)
	if err != nil {
		return err
	}
	sY, err := curves.ScalarUnmarshalBinary(sYBytes)
	if err != nil {
		return err
	}

	mp.eC = eC
	mp.tSigma = tSigma
	mp.tRho = tRho
	mp.sSigma = sSigma
	mp.sRho = sRho
	mp.sDeltaSigma = sDeltaSigma
	mp.sDeltaRho = sDeltaRho
	mp.sY = sY

	return nil
}

// MembershipProofFinal contains values that are input to Fiat-Shamir Heuristic.
type MembershipProofFinal struct {
	accumulator    curves.Point
	eC             curves.Point
	tSigma         curves.Point
	tRho           curves.Point
	capRE          curves.Scalar
	capRSigma      curves.Point
	capRRho        curves.Point
	capRDeltaSigma curves.Point
	capRDeltaRho   curves.Point
}

// WriteChallengeContributionToTranscript computes Fiat-Shamir Heuristic taking input values of MembershipProofFinal.
func (m *MembershipProofFinal) WriteChallengeContributionToTranscript(transcript *merlin.Transcript) {
	writeChallengeContributionToTranscript(&[9][]byte{
		m.accumulator.ToAffineCompressed(),
		m.eC.ToAffineCompressed(),
		m.tSigma.ToAffineCompressed(),
		m.tRho.ToAffineCompressed(),
		m.capRE.Bytes(),
		m.capRSigma.ToAffineCompressed(),
		m.capRRho.ToAffineCompressed(),
		m.capRDeltaSigma.ToAffineCompressed(),
		m.capRDeltaRho.ToAffineCompressed(),
	}, transcript,
	)
}

func writeChallengeContributionToTranscript(contributions *[9][]byte, transcript *merlin.Transcript) {
	transcript.AppendMessage([]byte("V"), contributions[0])
	transcript.AppendMessage([]byte("Ec"), contributions[1])
	transcript.AppendMessage([]byte("T_sigma"), contributions[2])
	transcript.AppendMessage([]byte("T_rho"), contributions[3])
	transcript.AppendMessage([]byte("R_E"), contributions[4])
	transcript.AppendMessage([]byte("R_sigma"), contributions[5])
	transcript.AppendMessage([]byte("R_rho"), contributions[6])
	transcript.AppendMessage([]byte("R_delta_sigma"), contributions[7])
	transcript.AppendMessage([]byte("R_delta_rho"), contributions[8])
}
