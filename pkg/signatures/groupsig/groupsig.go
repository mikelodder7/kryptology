package groupsig

import (
	"github.com/gtank/merlin"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
)

type GroupSignatureScheme string

const (
	BBS GroupSignatureScheme = "Boneh-Boyen-Shacum (BBS)"
	PS  GroupSignatureScheme = "Pointcheval-Sanders (PS)"
)

// SecretKey implements the secret key of a short group signing scheme. We assume the message count is constant.
type SecretKey interface {
	Type() GroupSignatureScheme
	Curve() (*curves.PairingCurve, error)
	MessageCount() int
	PublicKey() PublicKey
	Sign(messages []curves.Scalar) (Signature, error)
}

// PublicKey implements the public key of a short group signing scheme. We assume the message count is constant.
type PublicKey interface {
	Type() GroupSignatureScheme
	Curve() (*curves.PairingCurve, error)
	MessageCount() int
}

// Signature implements a short group signature. We assume the total number of messages doesn't change.
type Signature interface {
	Type() GroupSignatureScheme
	Curve() (*curves.PairingCurve, error)
	Verify(publicKey PublicKey, messages []curves.Scalar) error
	// Unblind accepts a blinder, and unblinds the signature according to its type.
	Unblind(blinder common.SignatureBlinding) (Signature, error)
}

// BlindGroupSigner contains the data used for computing
// a blind signature and verifying proof of hidden messages from
// a future signature holder. A potential holder commits to messages
// that the signer will not know during the signing process
// rendering them hidden, but requires the holder to
// prove knowledge of those messages so a malicious party
// doesn't add just random data from anywhere.
type BlindGroupSigner interface {
	Type() GroupSignatureScheme
	VerifyProofsOfHiddenMessages(publicKey PublicKey, hiddenMessageIndices []int, nonce common.Nonce) error
	Sign(secretKey SecretKey, knownMessages map[int]common.ProofMessage, nonce common.Nonce) (Signature, error)
}

// PokSignatureBuilder a.k.a. Proof of Knowledge of a Signature
// is used by the prover to convince a verifier
// that they possess a valid signature and
// can selectively disclose a set of signed messages.
type PokSignatureBuilder interface {
	Type() GroupSignatureScheme
	// WriteChallengeContribution writes challenge contribution to a transcript which may or may not have anything in it.
	WriteChallengeContribution(transcript *merlin.Transcript) error
	// GenerateProof accepts a challenge scalar, generates schnorr proofs and finishes the pok.
	GenerateProof(challenge common.Challenge) (PokSignature, error)
}

// PokSignature is the actual proof that can be used by the verifier
// to verify (i) schnorr proofs of hidden messages and (ii) whether the blinded signature is valid.
type PokSignature interface {
	Type() GroupSignatureScheme
	Curve() (*curves.PairingCurve, error)
	// WriteProofContribution recomputes the commitment and writes it to a transcript which may or may not have in it.
	WriteProofContribution(publicKey PublicKey, challenge common.Challenge, revealedMessages map[int]curves.Scalar, transcript *merlin.Transcript) error
	// VerifySignatureProof verifies that the blinded signature is a valid signature.
	VerifySignatureProof(publicKey PublicKey, revealedMessages map[int]curves.Scalar) error
	GetHiddenMessageProofs(publicKey PublicKey, revealedMessages map[int]curves.Scalar) map[int]curves.Scalar

	// TODO: Add Challenge to the proof, then for the straightforward usecase, have the verify function use the challenge from the proof
	//       and pass that to the WriteProofContribution function.
	// TODO: VerifySchnorrProofs
	// TODO: Verify
}
