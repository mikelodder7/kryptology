package one_round_frost

import (
	"fmt"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ted25519/frost"
)

// Coordinator is an entity responsible for performing coordination
// among signers and for aggregating signature shares at the end of
// the protocol, resulting in the final signature. This party may be
// a signer themselves or an external party.
type Coordinator struct {
	threshold        uint32 // threshold is the threshold number
	curve            *curves.Curve
	challengeDeriver frost.ChallengeDeriver
	verificationKey  curves.Point
	commitments      map[uint32][]*SigningCommitment // Store a bunch of commitments from all signers.
	bound            uint32
	limit            uint32
}

// NewCoordinator creates a coordinator.
func NewCoordinator(
	vk curves.Point,
	cur *curves.Curve,
	thresh uint32,
	limit uint32,
	challengeDeriver frost.ChallengeDeriver,
	commitments map[uint32][]*SigningCommitment,
	bound uint32,
) (*Coordinator, error) {
	// Checking the input commitments are not empty
	if len(commitments) == 0 || uint32(len(commitments)) != thresh {
		return nil, fmt.Errorf("mismatch between length of input commitments and threshold")
	}

	for id, commitment := range commitments {
		if len(commitment) == 0 || uint32(len(commitment)) != bound {
			return nil, fmt.Errorf("mismatch between length of input commitments and bound for id %d", id)
		}
	}

	return &Coordinator{
		threshold:        thresh,
		curve:            cur,
		challengeDeriver: challengeDeriver,
		verificationKey:  vk,
		commitments:      commitments,
		bound:            bound,
		limit:            limit,
	}, nil
}

// DistributeCommitments fetches commitment pair for each signer for each signing round.
func (coordinator *Coordinator) DistributeCommitments() (map[uint32]*SigningCommitment, error) {
	// Make sure coordinator is not empty
	if coordinator == nil || coordinator.curve == nil || coordinator.commitments == nil {
		return nil, fmt.Errorf("nil coordinator")
	}

	// Check each signer's commitments, if it's empty, report error
	// Otherwise, fetch the commitments for each signer
	result := make(map[uint32]*SigningCommitment, coordinator.threshold)
	for id, commitment := range coordinator.commitments {
		if len(commitment) == 0 {
			return nil, fmt.Errorf("not enough commitments for usage for id %d", id)
		}
		// fetch the first commitment pair
		signingCommitment := &SigningCommitment{
			capDi: commitment[0].capDi,
			capEi: commitment[0].capEi,
		}
		result[id] = signingCommitment

		// remove the first commitment pair
		coordinator.commitments[id] = removeFirstSigningCommitment(coordinator.commitments[id], 0)
	}

	return result, nil
}

// removeFirstSigningCommitment removes first element from a SigningCommitment slice.
func removeFirstSigningCommitment(slice []*SigningCommitment, i int) []*SigningCommitment {
	copy(slice[i:], slice[i+1:])
	return slice[:len(slice)-1]
}

// Aggregate is run by a coordinator to aggregate signature shares and generate a valid Schnorr signature.
func (coordinator *Coordinator) Aggregate(capR curves.Point, shares map[uint32]*SignatureShare, msg []byte) (*Signature, error) {
	// Make sure the coordinator is not empty
	if coordinator == nil || coordinator.curve == nil {
		return nil, internal.ErrNilArguments
	}

	// Make sure msg is not empty
	if len(msg) == 0 {
		return nil, internal.ErrNilArguments
	}

	// Check no empty share or zero share
	for _, share := range shares {
		if share.zi == nil || share.zi.IsZero() {
			return nil, fmt.Errorf("some signature share is nil or zero")
		}
	}

	// Compute sum(zi)
	z := coordinator.curve.NewScalar()
	for _, share := range shares {
		zi := share.zi
		z = z.Add(zi)
	}

	return &Signature{
		capR,
		z,
	}, nil
}

// Verify checks the signature.
func Verify(curve *curves.Curve, vk curves.Point, msg []byte, signature *Signature) (bool, error) {
	if vk == nil || msg == nil || len(msg) == 0 || signature.capR == nil || signature.z == nil {
		return false, fmt.Errorf("invalid input")
	}
	z := signature.z
	capR := signature.capR

	// Compute c = H(m, R)
	c, err := frost.DeriveChallenge(msg, vk, capR)
	if err != nil {
		return false, err
	}

	// R' = z*G - c*vk
	zG := curve.ScalarBaseMult(z)
	cvk := vk.Mul(c.Neg())
	tempR := zG.Add(cvk)

	// c' = H(m, R')
	tempC, err := frost.DeriveChallenge(msg, vk, tempR)
	if err != nil {
		return false, err
	}

	// Check c == c'
	if tempC.Cmp(c) != 0 {
		return false, fmt.Errorf("invalid signature: c != c'")
	}
	return true, nil
}
