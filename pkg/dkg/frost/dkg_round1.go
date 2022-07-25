//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"fmt"
	"reflect"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

// Round3Bcast are values that are broadcast to all other participants
// after round1 completes.
type Round3Bcast struct {
	Verifiers *sharing.FeldmanVerifier
	Wi, Ci    curves.Scalar
}

type Round3Result struct {
	Broadcast *Round3Bcast
	P2P       *sharing.ShamirShare
}

func (result *Round3Result) Encode() ([]byte, error) {
	gob.Register(result.Broadcast.Verifiers.Commitments[0]) // just the point for now
	gob.Register(result.Broadcast.Ci)
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(result); err != nil {
		return nil, errors.Wrap(err, "couldn't encode round 1 broadcast")
	}
	return buf.Bytes(), nil
}

func (result *Round3Result) Decode(input []byte) error {
	buf := bytes.NewBuffer(input)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(result); err != nil {
		return errors.Wrap(err, "couldn't encode round 1 broadcast")
	}
	return nil
}

// Round3P2PSend are values that are P2PSend to all other participants
// after round1 completes.
type Round3P2PSend = map[uint32]*sharing.ShamirShare

// Round3FrostDkgFirstRound validates openings, generate the fixed string and then implements dkg round 1 of FROST DKG.
func (dp *DkgParticipant) Round3FrostDkgFirstRound(secret []byte, openings map[uint32]*core.Witness) (*Round3Bcast, Round3P2PSend, error) {
	// Make sure dkg participant is not empty
	if dp == nil || dp.Curve == nil || dp.preRoundCommitments == nil {
		return nil, nil, internal.ErrNilArguments
	}

	// Make sure round number is correct
	if dp.round != 3 {
		return nil, nil, internal.ErrInvalidRound
	}

	// Check length of openings
	if openings == nil || uint32(len(openings)) != dp.Limit {
		return nil, nil, fmt.Errorf("invalid length of openings")
	}

	// Check each opening is not empty
	for _, opening := range openings {
		if opening == nil {
			return nil, nil, fmt.Errorf("some opening is nil")
		}
	}

	// Check number of participants
	if uint32(len(dp.participantIds)) > dp.feldman.Limit || uint32(len(dp.participantIds)) < dp.feldman.Threshold {
		return nil, nil, fmt.Errorf("length of dp.otherParticipantShares + 1 should be equal to feldman limit")
	}

	// Check participantIds are the same as Ids of the input openings
	for _, id := range dp.participantIds {
		_, containsId := openings[id]
		if !containsId {
			return nil, nil, fmt.Errorf("invalid openings doesn't contain id %d", id)
		}
	}

	// Validate each opening
	var appendHashInput []byte
	for id, opening := range openings {
		if id == dp.Id {
			continue
		}
		commitment := dp.preRoundCommitments[id]
		ok, err := core.Open(*commitment, *opening)
		// The commitment should be no error
		if err != nil {
			return nil, nil, fmt.Errorf("there is error in opening with id %d", id)
		}
		// The commitment should verify
		if !ok {
			return nil, nil, fmt.Errorf("failed to open with id %d", id)
		}
	}

	// Concatenate values
	for _, id := range dp.participantIds {
		appendHashInput = append(appendHashInput, openings[id].Msg...)
	}

	// Compute the fixed string and store it
	h := sha3.New256()
	_, _ = h.Write(appendHashInput)
	ctx := h.Sum(nil)

	// Store ctx
	dp.ctx = ctx

	// If secret is nil, sample a new one
	// If not, check secret is valid
	var s curves.Scalar
	var err error
	if secret == nil {
		s = dp.Curve.Scalar.Random(crand.Reader)
	} else {
		s, err = dp.Curve.Scalar.SetBytes(secret)
		if err != nil {
			return nil, nil, err
		}
		if s.IsZero() {
			return nil, nil, internal.ErrZeroValue
		}
	}

	// Step 1 - (Aj0,...Ajt), (xi1,...,xin) <- FeldmanShare(s)
	// We should validate types of Feldman curve scalar and participant's curve scalar.
	if reflect.TypeOf(dp.feldman.Curve.Scalar) != reflect.TypeOf(dp.Curve.Scalar) {
		return nil, nil, fmt.Errorf("feldman scalar should have the same type as the dkg participant scalar")
	}
	verifiers, shares, err := dp.feldman.Split(s, crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Store Verifiers and shares
	dp.verifiers = verifiers
	dp.secretShares = shares

	// Step 2 - Sample ki <- Z_q
	ki := dp.Curve.Scalar.Random(crand.Reader)

	// Step 3 - Compute Ri = ki*G
	Ri := dp.Curve.ScalarBaseMult(ki)

	// Step 4 - Compute Ci = H(i, CTX, g^{a_(i,0)}, R_i), where CTX is fixed context string
	var msg []byte
	// Append participant id
	msg = append(msg, byte(dp.Id))
	// Append CTX
	msg = append(msg, dp.ctx...)
	// Append a_{i,0}*G
	msg = append(msg, verifiers.Commitments[0].ToAffineCompressed()...)
	// Append Ri
	msg = append(msg, Ri.ToAffineCompressed()...)
	// Hash the message and get Ci
	ci := dp.Curve.Scalar.Hash(msg)

	// Step 5 - Compute Wi = ki+a_{i,0}*c_i mod q. Note that a_{i,0} is the secret.
	// Note: We have to compute scalar in the following way when using ed25519 curve, rather than scalar := dp.Scalar.Mul(s, Ci)
	// there is an invalid encoding error when we compute scalar as above.
	wi := s.MulAdd(ci, ki)

	// Step 6 - Broadcast (Ci, Wi, Ci) to other participants
	round1Bcast := &Round3Bcast{
		verifiers,
		wi,
		ci,
	}

	// Step 7 - P2PSend f_i(j) to each participant Pj and keep (i, f_j(i)) for himself
	p2pSend := make(Round3P2PSend, len(dp.participantIds)-1)
	for _, id := range dp.participantIds {
		if dp.Id == id {
			continue
		}
		p2pSend[id] = shares[id-1]
	}

	// Update internal state
	dp.round = 4

	// return
	return round1Bcast, p2pSend, nil
}
