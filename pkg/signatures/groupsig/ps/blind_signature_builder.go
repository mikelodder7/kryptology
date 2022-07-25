// Blind PS signatures that are implemented here are a combination of
// section 6.1 of https://eprint.iacr.org/2015/525.pdf and
// section 4.2 of https://eprint.iacr.org/2017/1197.pdf
package ps

/*
   r = number of messages (fixed).
   Secret key: {x, y_1, ... y_{r+1}}
   Public key: {Y_1, ..., Y_r, \widetilde{X}, \widetilde{Y\prime}, \widetilde{Y_1}, ..., \widetilde{Y_r}}} where Y_i = y_i * G_1 and \widetilde{X} = x * G_1
1. Holder:
   1. b <- G_1
   2. C = bG_1 + \Sigma m_i * Y_i where m_i is the i'th hidden message
   3. sends C and proofs of knowledge of the commitment to the issuer.
2. Issuer:
   0. Accepts known message map M=map[int]knownMessage whose keys are indices of messages that are not hidden to the message itself
   1. u = H(x || y_1 || ... || y_{r+1} || m_0 || ... || m_i) where m_i is the i'th value of M
   2. m' = H(u || m_0 || ... || m _i) where m_i is the i'th value of M
   3. Sigma1 = uG1
   4. Sigma2' = (x + (\Sigma y_i * m_i) + (y_[r+1] * m'))Sigma1 + uC
   5. Sends sigma' = (Sigma1, Sigma2') back to Holder
3. Holder:
   1. Sigma2 = Sigma2' - bSigma1
   2. verifies sigma = (Sigma1, Sigma2)
*/

import (
	"io"
	"sort"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// BlindSigner contains the data used for computing
// a blind signature and verifying proof of hidden messages from
// a future signature holder. A potential holder commits to messages
// that the signer will not know during the signing process
// rendering them hidden, but requires the holder to
// prove knowledge of those messages so a malicious party
// doesn't add just random data from anywhere.
type BlindSigner struct {
	// The blinded signature commitment
	commitment common.Commitment
	// The challenge hash for the Fiat-Shamir heuristic
	challenge curves.Scalar
	// The proofs of hidden messages.
	proofs []curves.Scalar
}

func (*BlindSigner) Type() groupsig.GroupSignatureScheme {
	return groupsig.PS
}

// VerifyProofsOfHiddenMessages validates proofs of hidden messages.
func (c *BlindSigner) VerifyProofsOfHiddenMessages(publicKey groupsig.PublicKey, hiddenMessageIndices []int, nonce common.Nonce) error {
	if publicKey.Type() != groupsig.PS {
		return errors.Errorf("publicKey has type '%s' where expected type is '%s'", publicKey.Type(), groupsig.PS)
	}
	psPublicKey, ok := publicKey.(*PublicKey)
	if !ok {
		return errors.New("failed type assertion")
	}

	curve, err := psPublicKey.Curve()
	if err != nil {
		return errors.WithStack(err)
	}

	points := []curves.Point{c.commitment, curve.NewG1GeneratorPoint()}
	scalars := []curves.Scalar{c.challenge.Neg()}

	for _, index := range hiddenMessageIndices {
		if index < 0 || index > publicKey.MessageCount() {
			return errors.New("incorrect index")
		}
		points = append(points, psPublicKey.Ys[index])
	}
	scalars = append(scalars, c.proofs...)

	commitment := curve.NewG1GeneratorPoint().SumOfProducts(points, scalars)
	if commitment == nil {
		return errors.New("sum of products to produce commitment is nil")
	}
	challenge, err := produceBlindSignatureChallenge(curve, commitment.ToAffineCompressed(), c.commitment.ToAffineCompressed(), nonce)
	if err != nil {
		return errors.Wrap(err, "couldn't produce challenge")
	}

	if challenge.Cmp(c.challenge) != 0 {
		return errors.New("invalid proof")
	}
	return nil
}

// Sign creates a blind signature. `knownMessages` argument is a map of the index of the known message to the message itself.
func (c *BlindSigner) Sign(secretKey groupsig.SecretKey, knownMessages map[int]common.ProofMessage, nonce common.Nonce) (groupsig.Signature, error) {
	if secretKey.Type() != groupsig.PS {
		return nil, errors.Errorf("secret key has type '%s' where the expected type is '%s'", secretKey.Type(), groupsig.PS)
	}
	psSecretKey, ok := secretKey.(*SecretKey)
	if !ok {
		return nil, errors.New("failed type assertion")
	}

	if psSecretKey == nil || knownMessages == nil || len(knownMessages) == 0 || len(knownMessages) > len(psSecretKey.ys) {
		return nil, internal.ErrNilArguments
	}

	hiddenMessageIndices := []int{}
	for i := 0; i < secretKey.MessageCount(); i++ {
		_, exists := knownMessages[i]
		if !exists {
			hiddenMessageIndices = append(hiddenMessageIndices, i)
			continue
		}
		if i < 0 || i >= secretKey.MessageCount() {
			return nil, errors.New("invalid message count")
		}
	}

	curve, err := secretKey.Curve()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := c.VerifyProofsOfHiddenMessages(secretKey.PublicKey(), hiddenMessageIndices, nonce); err != nil {
		return nil, errors.Wrap(err, "proof verification fails")
	}

	scalarsToBeHashedForMPrime := []curves.Scalar{}

	// step 2.1
	scalarsToBeHashedForU := []curves.Scalar{psSecretKey.x, psSecretKey.yPrime}
	for _, y := range psSecretKey.ys {
		scalarsToBeHashedForU = append(scalarsToBeHashedForU, y)
	}
	for _, message := range knownMessages {
		scalarsToBeHashedForU = append(scalarsToBeHashedForU, message.GetMessage())
		scalarsToBeHashedForMPrime = append(scalarsToBeHashedForMPrime, message.GetMessage())
	}
	u, err := hashScalars(curve, scalarsToBeHashedForU)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't produce u")
	}

	// step 2.2
	scalarsToBeHashedForMPrime = append(scalarsToBeHashedForMPrime, u)
	mPrime, err := hashScalars(curve, scalarsToBeHashedForMPrime)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't produce mPrime")
	}

	// step 2.3
	sigma1 := curve.ScalarG1BaseMult(u)

	// step 2.4
	multiplicand, ok := psSecretKey.x.(curves.Scalar)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	for i, message := range knownMessages {
		multiplicand = multiplicand.Add(psSecretKey.ys[i].Mul(message.GetMessage()))
	}
	multiplicand = multiplicand.Add(psSecretKey.yPrime.Mul(mPrime))

	uC := c.commitment.Mul(u)

	sigma2Prime, ok := sigma1.Mul(multiplicand).Add(uC).(curves.PairingPoint)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}

	return &Signature{
		MPrime: mPrime,
		Sigma1: sigma1,
		Sigma2: sigma2Prime,
	}, nil
}

// NewBlindSigner applies the Commitment of hidden messages as well as mPrime and creates the proof.
// The blind signer will use the BlindSigner object to verify the proof and include
// the commitment in the signature. The context creator will then use the blinded signature
// alongside the returned blinding factor from this method to unblind the signature.
func NewBlindSigner(publicKey *PublicKey, hiddenMessages map[int]common.ProofMessage, nonce common.Nonce, reader io.Reader) (*BlindSigner, common.SignatureBlinding, error) {
	if hiddenMessages == nil || len(hiddenMessages) < 1 || len(hiddenMessages) > len(publicKey.Ys) || reader == nil {
		return nil, nil, internal.ErrNilArguments
	}

	curve := curves.GetPairingCurveByName(publicKey.XTilde.CurveName())
	if curve == nil {
		return nil, nil, errors.New("curve is nil")
	}

	committing := common.NewProofCommittedBuilder(&curves.Curve{
		Scalar: curve.Scalar,
		Point:  curve.NewG1GeneratorPoint(),
		Name:   curve.Name,
	})

	hiddenMessageIndices := []int{}
	for i := range hiddenMessages {
		if i >= len(publicKey.Ys) {
			return nil, nil, errors.New("invalid index")
		}
		hiddenMessageIndices = append(hiddenMessageIndices, i)
	}
	sort.Ints(hiddenMessageIndices)

	// step 1.1
	b := curve.Scalar.Random(reader)

	// step 1.2
	G1 := curve.NewG1GeneratorPoint() // bG1 will be produced within SumOfProducts method
	if err := committing.CommitRandom(G1, reader); err != nil {
		return nil, nil, errors.WithStack(err)
	}

	secrets := []curves.Scalar{b}
	points := []curves.Point{G1}

	for _, index := range hiddenMessageIndices {
		message := hiddenMessages[index].GetMessage()
		if message == nil {
			return nil, nil, errors.New("message is nil")
		}
		secrets = append(secrets, message)
		points = append(points, publicKey.Ys[index])
		if err := committing.CommitRandom(publicKey.Ys[index], reader); err != nil {
			return nil, nil, errors.WithStack(err)
		}
	}

	// Create a random commitment, compute challenges and response.
	// The proof of knowledge consists of a commitment and responses
	// Holder and signer engage in a proof of knowledge for `commitment`
	commitment := G1.SumOfProducts(points, secrets)
	if commitment == nil {
		return nil, nil, errors.New("sum of products to produce a commitment is nil")
	}
	challenge, err := produceBlindSignatureChallenge(curve, committing.GetChallengeContribution(), commitment.ToAffineCompressed(), nonce)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	proofs, err := committing.GenerateProof(challenge, secrets)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	blinding, ok := b.(common.SignatureBlinding)
	if !ok {
		return nil, nil, errors.New("unable to create signature blidning")
	}

	return &BlindSigner{
		commitment: commitment,
		challenge:  challenge,
		proofs:     proofs,
	}, blinding, nil
}

func produceBlindSignatureChallenge(curve *curves.PairingCurve, randomCommitment, commitment []byte, nonce common.Nonce) (curves.Scalar, error) {
	transcript := merlin.NewTranscript("new ps blind signature")
	transcript.AppendMessage([]byte("random commitment"), randomCommitment)
	transcript.AppendMessage([]byte("commitment"), commitment)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("blind signature context challenge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return challenge, nil
}
