package frost

import (
	"crypto/rand"
	"fmt"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
)

// In FROST DKG we need to generate a fixed string to prevent replay attacks. This fixed string
// should be freshly generated every time. This file implements one more round for all dkg participants
// to collaboratively generate a fixed string without a trusted third party.
// The steps are referred from https://crypto.stackexchange.com/questions/767/how-to-fairly-select-a-random-number-for-a-game-without-trusting-a-third-party
// and it works as follows:
// 1. Each party picks a random value, and publicly commits to it.
// In detail: the party Pi should pick two 32 random-byte value ai and ri and broadcast yi = Commit(i||ai||ri), a commitment to random value ai using randomness ri.
// 2. After everyone has received everyone else's commitments (yi values), then each party should open their commitment by broadcasting (ai, ri).
// In detail: once party Pi has received all n-1 commitments, he/she broadcasts (ai, ri). Everyone checks that each openning is consistent with the earlier commitment yi.
// If anyone detects any inconsistency, or if anyone doesn't finish the protocol, you have to call the whole thing off and punish whoever didn't follow the instructions.
// 3. Finally, compute R = Hash(r1, r2, ..., rn). The value R is the random value that everyone has jointly generated.
const randomValueSize = 32

func (dp *DkgParticipant) Round1Commit() (*core.Commitment, error) {
	// Make sure dkg participant is not empty
	if dp == nil {
		return nil, internal.ErrNilArguments
	}

	// Check state
	if dp.round != 1 {
		return nil, internal.ErrInvalidRound
	}

	randomValue := [randomValueSize]byte{}
	if _, err := rand.Read(randomValue[:]); err != nil {
		return nil, fmt.Errorf("fail to sample random value ai")
	}

	// Commit
	var bytes []byte
	bytes = append(bytes, byte(dp.Id))
	bytes = append(bytes, randomValue[:]...)
	commitment, witness, err := core.Commit(bytes)
	if err != nil {
		return nil, fmt.Errorf("fail to commit")
	}

	// store witness
	dp.preRoundWitness = witness

	// update internal state
	dp.round = 2

	return &commitment, nil
}

func (dp *DkgParticipant) Round2Open(commitments map[uint32]*core.Commitment) (*core.Witness, error) {
	// Make sure dkg participant is not empty
	if dp == nil || dp.preRoundWitness == nil {
		return nil, internal.ErrNilArguments
	}

	// Check state
	if dp.round != 2 {
		return nil, internal.ErrInvalidRound
	}

	// Check length of commitments
	if commitments == nil || uint32(len(commitments)) != dp.Limit {
		return nil, fmt.Errorf("invalid length of commitments")
	}

	// Check each commitment
	for _, commitment := range commitments {
		if commitment == nil {
			return nil, fmt.Errorf("some commitment is invalid")
		}
	}

	// store commitments
	dp.preRoundCommitments = commitments

	// update internal state
	dp.round = 3

	// retrieve opening
	return dp.preRoundWitness, nil
}
