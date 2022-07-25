// Proof of knowledge of PS signatures that are implemented here
// are a combination of section 6.2 of https://eprint.iacr.org/2015/525.pdf
// and section 4.2 of https://eprint.iacr.org/2017/1197.pdf
package ps

import (
	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// PokSignature is the actual proof that can be used by the verifier
// to verify (i) schnorr proofs of hidden messages and (ii) whether the blinded signature is valid.
type PokSignature struct {
	Sigma1Prime, Sigma2Prime curves.PairingPoint
	Commitment               common.Commitment
	// schnorr proofs for selective disclosure. Contains all hidden messages, mPrime and t.
	SchnorrProofs []curves.Scalar
}

func (*PokSignature) Type() groupsig.GroupSignatureScheme {
	return groupsig.PS
}

func (pok *PokSignature) Curve() (*curves.PairingCurve, error) {
	curve := curves.GetPairingCurveByName(pok.Sigma1Prime.CurveName())
	if curve == nil {
		return nil, errors.New("curve is nil")
	}
	return curve, nil
}

// WriteProofContribution recomputes the commitment and writes it to a transcript which may or may not have anything in it. It does not write nonce.
func (pok *PokSignature) WriteProofContribution(publicKey groupsig.PublicKey, challenge common.Challenge, revealedMessages map[int]curves.Scalar, transcript *merlin.Transcript) error {
	psPublicKey, ok := publicKey.(*PublicKey)
	if !ok {
		return errors.New("failed type assertion")
	}

	curve, err := publicKey.Curve()
	if err != nil {
		return errors.WithStack(err)
	}
	pokCurve, err := pok.Curve()
	if err != nil {
		return errors.WithStack(err)
	}
	if pokCurve.Name != curve.Name {
		return errors.New("pok and public key are not the same curve")
	}

	points := []curves.Point{pok.Commitment, curve.NewG2GeneratorPoint(), psPublicKey.YTildePrime}
	scalars := []curves.Scalar{challenge.Neg()}

	for i, YTilde := range psPublicKey.YTildes {
		if _, isRevealed := revealedMessages[i]; !isRevealed {
			points = append(points, YTilde)
		}
	}
	scalars = append(scalars, pok.SchnorrProofs...)
	commitment := points[0].SumOfProducts(points, scalars)
	if commitment == nil {
		return errors.New("sum of products to produce commitment is nil")
	}

	writeToTranscript(commitment.ToAffineCompressed(), pok.Commitment.ToAffineCompressed(), transcript)
	return nil
}

// VerifySignatureProof verifies that the blinded signature is a valid signature.
// To verify whether schnorr proofs of all messages is valid, manually compute the challenge and check for equality.
func (pok *PokSignature) VerifySignatureProof(publicKey groupsig.PublicKey, revealedMessages map[int]curves.Scalar) error {
	psPublicKey, ok := publicKey.(*PublicKey)
	if !ok {
		return errors.New("failed type assertion")
	}
	if len(pok.SchnorrProofs)+len(revealedMessages) != len(psPublicKey.Ys)+2 { // one for tG2 and one for mPrime*YTildePrime
		return errors.Errorf("#proofs(=%d) + #revealed messages(=%d) != #messages(=%d) + 2", len(pok.SchnorrProofs), len(revealedMessages), len(psPublicKey.Ys))
	}
	curve, err := publicKey.Curve()
	if err != nil {
		return errors.WithStack(err)
	}
	pokCurve, err := pok.Curve()
	if err != nil {
		return errors.WithStack(err)
	}
	if pokCurve.Name != curve.Name {
		return errors.New("pok and public key are not the same curve")
	}

	if pok.Sigma1Prime.IsIdentity() {
		return errors.New("sigma1' can't be equal to the identity element of G1")
	}
	if pok.Sigma2Prime.IsIdentity() {
		return errors.New("sigma2' can't be equal to the identity element of G1")
	}
	if err := checkGivenPublicKeyForForgeryAttack(psPublicKey); err != nil {
		return errors.WithStack(err)
	}
	if pok.Commitment.IsIdentity() {
		return errors.New("commitment can't be equal to the identity element of G2")
	}

	points := []curves.Point{psPublicKey.XTilde, pok.Commitment}
	scalars := []curves.Scalar{curve.Scalar.New(1), curve.Scalar.New(1)}

	for i, message := range revealedMessages {
		if i >= len(psPublicKey.YTildes) {
			return errors.New("invalid index")
		}
		scalars = append(scalars, message)
		points = append(points, psPublicKey.YTildes[i])
	}

	rhs, ok := psPublicKey.XTilde.SumOfProducts(points, scalars).(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}

	G2Inv, ok := curve.NewG2GeneratorPoint().Neg().(curves.PairingPoint)
	if !ok {
		return errors.New("incorrect type conversion")
	}

	result := pok.Sigma1Prime.MultiPairing(pok.Sigma1Prime, rhs, pok.Sigma2Prime, G2Inv)
	if !result.IsOne() {
		return errors.New("multipairing is not one")
	}
	return nil
}

// GetHiddenMessageProofs returns the schnorr proofs for all hidden messages.
func (pok *PokSignature) GetHiddenMessageProofs(
	publicKey groupsig.PublicKey,
	revealedMessages map[int]curves.Scalar,
) map[int]curves.Scalar {
	// offset by 2 since the first two are for blinding factors used by the signature.
	hiddenMsgPfs := make(map[int]curves.Scalar, publicKey.MessageCount()-len(revealedMessages)-2)
	j := 2
	for i := 0; i < publicKey.MessageCount(); i++ {
		if _, contains := revealedMessages[i]; contains {
			continue
		}
		hiddenMsgPfs[i] = pok.SchnorrProofs[j]
		j++
	}
	return hiddenMsgPfs
}
