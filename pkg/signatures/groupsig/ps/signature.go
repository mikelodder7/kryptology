// Package ps is an implementation of ps https://eprint.iacr.org/2017/1197.pdf
package ps

import (
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// Signature is a PS signature.
type Signature struct {
	// In section 4.2 of https://eprint.iacr.org/2017/1197.pdf, the signature is a tuple of (m', sigma1 and sigma2)
	// where m' and sigma1 are randomly generated.
	// Here, to get m', we hash all the messages together (section 4.3). And to get sigma1, we hash m' to a curve point.
	// This makes the signature deterministic, but we need to store m' and sigma1 for blind signatures
	MPrime         curves.PairingScalar
	Sigma1, Sigma2 curves.PairingPoint
}

func (*Signature) Type() groupsig.GroupSignatureScheme {
	return groupsig.PS
}

func (sig *Signature) Curve() (*curves.PairingCurve, error) {
	curve := curves.GetPairingCurveByName(sig.Sigma1.CurveName())
	if curve == nil {
		return nil, errors.New("curve is nil")
	}
	return curve, nil
}

// Verify verifies the ps signature.
func (sig *Signature) Verify(publicKey groupsig.PublicKey, messages []curves.Scalar) error {
	if publicKey.Type() != groupsig.PS {
		return errors.Errorf("given public key has the type '%s' where as we need '%s'", publicKey.Type(), groupsig.PS)
	}
	psPublicKey, ok := publicKey.(*PublicKey)
	if !ok {
		return errors.New("failed type assertion")
	}
	return Verify(sig, psPublicKey, messages)
}

// Unblind accepts a blinder, and unblinds the ps signature.
func (sig *Signature) Unblind(blinder common.SignatureBlinding) (groupsig.Signature, error) {
	return Unblind(sig, blinder)
}

// Sign produces a PS signature given a PS secret key, the messages to be signed and a pairing curve.
func Sign(secretKey *SecretKey, messages []curves.Scalar) (*Signature, error) {
	if len(messages) != len(secretKey.ys) {
		return nil, errors.New("size of the message vector is not equal to the y vector")
	}

	curve, err := secretKey.Curve()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// m' <- Z_p but instead we will hash all the messages together.
	mPrime, err := hashScalars(curve, messages)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't produce mPrime")
	}

	// h <- G*_1 but instead we hash m' to G1 curve
	sigma1, ok := curve.PointG1.Hash(mPrime.Bytes()).(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}

	// h^(x + sigma^r_j=1 y_j . m_j + y' . m')
	exponent, ok := secretKey.x.(curves.Scalar)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	for j, m := range messages {
		exponent = exponent.Add(secretKey.ys[j].Mul(m))
	}
	exponent = exponent.Add(secretKey.yPrime.Mul(mPrime))

	sigma2, ok := sigma1.Mul(exponent).(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}

	return &Signature{
		MPrime: mPrime,
		// Sigma1 == h
		Sigma1: sigma1,
		// Sigma2 == h^exponent
		Sigma2: sigma2,
	}, nil
}

// Verify returns an error if the provided PS signature is invalid given the PS public key and messages.
// It returns nil if verification is successful.
func Verify(signature *Signature, publicKey *PublicKey, messages []curves.Scalar) error {
	if len(messages) != len(publicKey.YTildes) {
		return errors.New("size of the message vector is not equal to the yG2 vector")
	}

	curve, err := publicKey.Curve()
	if err != nil {
		return errors.WithStack(err)
	}

	// sigma_1 != 1_G_1
	if signature.Sigma1.IsIdentity() {
		return errors.New("sigma1 can't be equal to the identity element of G1")
	}

	// good practice.
	if signature.Sigma2.IsIdentity() {
		return errors.New("sigma2 can't be equal to the identity element of G1")
	}

	// preventing forgery attack.
	if err := checkGivenPublicKeyForForgeryAttack(publicKey); err != nil {
		return errors.WithStack(err)
	}

	// e(\sigma_1, \tilde{X} \cdot \prod_{j=1}^r \tilde{Y}_j^{m_j} \cdot \tilde{Y\prime}^{m\prime})

	points := []curves.Point{publicKey.XTilde, publicKey.YTildePrime}
	scalars := []curves.Scalar{curve.Scalar.New(1), signature.MPrime}

	for i, m := range messages {
		points = append(points, publicKey.YTildes[i])
		scalars = append(scalars, m)
	}

	rhs, ok := publicKey.XTilde.SumOfProducts(points, scalars).(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}

	sigma2Inv, ok := signature.Sigma2.Neg().(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}

	// `result` is equivalent to the equality check that the paper needs, but instead of computing two pairings and comparing them,
	// we will use the `MultiPairing` to just compute one pairing.
	result := signature.Sigma1.MultiPairing(signature.Sigma1, rhs, sigma2Inv, curve.NewG2GeneratorPoint())
	if !result.IsOne() {
		return errors.New("multipairing is not one")
	}

	return nil
}

// Unblind accepts a blinder, and unblinds the ps signature.
func Unblind(signature *Signature, blinder common.SignatureBlinding) (*Signature, error) {
	blindingPoint := signature.Sigma1.Mul(blinder)
	unblindedSigma2, ok := signature.Sigma2.Sub(blindingPoint).(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	return &Signature{
		MPrime: signature.MPrime,
		Sigma1: signature.Sigma1,
		Sigma2: unblindedSigma2,
	}, nil
}
