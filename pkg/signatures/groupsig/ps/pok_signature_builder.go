// Proof of knowledge of PS signatures that are implemented here
// are a combination of section 6.2 of https://eprint.iacr.org/2015/525.pdf
// and section 4.2 of https://eprint.iacr.org/2017/1197.pdf
package ps

import (
	"io"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// PokSignatureBuilder a.k.a. Proof of Knowledge of a Signature
// is used by the prover to convince a verifier
// that they possess a valid signature and
// can selectively disclose a set of signed messages.
type PokSignatureBuilder struct {
	selectiveDisclosureProofBuilder *common.ProofCommittedBuilder
	schnorrSecrets                  []curves.Scalar
	revealedMessages                map[int]curves.Scalar
	Proof                           *PokSignature
}

func (*PokSignatureBuilder) Type() groupsig.GroupSignatureScheme {
	return groupsig.PS
}

func (b *PokSignatureBuilder) Curve() (*curves.PairingCurve, error) {
	curve := curves.GetPairingCurveByName(b.Proof.Sigma1Prime.CurveName())
	if curve == nil {
		return nil, errors.New("curve is nil")
	}
	return curve, nil
}

// WriteChallengeContribution writes challenge contribution to a transcript which may or may not have anything in it. It does not write nonce.
func (b *PokSignatureBuilder) WriteChallengeContribution(transcript *merlin.Transcript) error {
	writeToTranscript(b.selectiveDisclosureProofBuilder.GetChallengeContribution(), b.Proof.Commitment.ToAffineCompressed(), transcript)
	return nil
}

// GenerateProof accepts a challenge scalar, generates schnorr proofs and finishes the pok.
func (b *PokSignatureBuilder) GenerateProof(challenge common.Challenge) (groupsig.PokSignature, error) {
	var err error
	b.Proof.SchnorrProofs, err = b.selectiveDisclosureProofBuilder.GenerateProof(challenge, b.schnorrSecrets)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't produce schnorr proofs of hidden messages")
	}
	return b.Proof, nil
}

// NewComposablePokSignature accepts a signature, and returns a PokSignatureBuilder which contains a partial pok (only the signature part). To complete the proof, write to transcript, derive challenge and call GenerateProof.
// It's called composable, because we want to the cover the use case that ties in various schnorr proofs through by having them share the same challenge hash.
func NewComposablePokSignature(signature *Signature, publicKey *PublicKey, messages []common.ProofMessage, reader io.Reader) (*PokSignatureBuilder, error) {
	if len(messages) != len(publicKey.Ys) {
		return nil, errors.New("number of messages isn't supported by the key")
	}

	curve := curves.GetPairingCurveByName(signature.Sigma1.CurveName())
	if curve == nil {
		return nil, errors.New("curve is nil")
	}

	var ok bool
	pok := &PokSignatureBuilder{
		selectiveDisclosureProofBuilder: common.NewProofCommittedBuilder(&curves.Curve{
			Scalar: curve.Scalar,
			Point:  curve.NewG2GeneratorPoint(),
			Name:   curve.Name,
		}),
		revealedMessages: map[int]curves.Scalar{},
		Proof:            &PokSignature{},
	}

	t := curve.Scalar.Random(reader)
	r := curve.Scalar.Random(reader)

	pok.Proof.Sigma1Prime, ok = signature.Sigma1.Mul(r).(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	pok.Proof.Sigma2Prime, ok = signature.Sigma2.Add(signature.Sigma1.Mul(t)).Mul(r).(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}

	G2 := curve.NewG2GeneratorPoint()
	// For t
	if err := pok.selectiveDisclosureProofBuilder.CommitRandom(G2, reader); err != nil {
		return nil, errors.WithStack(err)
	}
	pok.schnorrSecrets = []curves.Scalar{t, signature.MPrime}
	points := []curves.Point{G2, publicKey.YTildePrime}
	// For MPrime
	if err := pok.selectiveDisclosureProofBuilder.CommitRandom(publicKey.YTildePrime, reader); err != nil {
		return nil, errors.WithStack(err)
	}

	for i, message := range messages {
		if !message.IsHidden() {
			pok.revealedMessages[i] = message.GetMessage()
			continue
		}
		pok.schnorrSecrets = append(pok.schnorrSecrets, message.GetMessage())
		points = append(points, publicKey.YTildes[i])
		if err := pok.selectiveDisclosureProofBuilder.Commit(publicKey.YTildes[i], message.GetBlinding(reader)); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	pok.Proof.Commitment, ok = G2.SumOfProducts(points, pok.schnorrSecrets).(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}

	return pok, nil
}

// NewPokSignature accepts a signature and messages (some of which may be hidden) and returns proof of knowledge
// of the signature alongside schnorr proofs of the hidden messages.
func NewPokSignature(signature *Signature, publicKey *PublicKey, messages []common.ProofMessage, nonce common.Nonce, reader io.Reader) (groupsig.PokSignature, error) {
	transcript := merlin.NewTranscript("new ps pok signature")
	curve, err := signature.Curve()
	if err != nil {
		return nil, errors.Wrap(err, "couldn't get the curve")
	}

	pokSignatureBuilder, err := NewComposablePokSignature(signature, publicKey, messages, reader)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't construct pok signature builder")
	}

	if err := pokSignatureBuilder.WriteChallengeContribution(transcript); err != nil {
		return nil, errors.WithStack(err)
	}

	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't compute challenge")
	}

	return pokSignatureBuilder.GenerateProof(challenge)
}
