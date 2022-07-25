//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package frost is an implementation of the DKG part of  https://eprint.iacr.org/2020/852.pdf
package frost

import (
	"fmt"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

type DkgParticipant struct {
	round               int
	Curve               *curves.Curve
	participantIds      []uint32
	Id                  uint32
	SkShare             curves.Scalar
	VerificationKey     curves.Point
	VkShare             curves.Point
	feldman             *sharing.Feldman
	verifiers           *sharing.FeldmanVerifier
	secretShares        []*sharing.ShamirShare
	ctx                 []byte
	Threshold           uint32
	Limit               uint32
	preRoundWitness     *core.Witness
	preRoundCommitments map[uint32]*core.Commitment
}

func NewDkgParticipant(id, threshold uint32, curve *curves.Curve, participantIds []uint32) (*DkgParticipant, error) {
	// Check curve and participantIds are not nil
	if curve == nil || len(participantIds) == 0 {
		return nil, internal.ErrNilArguments
	}

	// Check id is among the participantIds
	result := false
	for _, pId := range participantIds {
		if id == pId {
			result = true
			break
		}
	}
	if !result {
		return nil, fmt.Errorf("invalid participantIds")
	}

	limit := uint32(len(participantIds))
	feldman, err := sharing.NewFeldman(threshold, limit, curve)
	if err != nil {
		return nil, err
	}

	return &DkgParticipant{
		Id:             id,
		round:          1,
		Curve:          curve,
		feldman:        feldman,
		participantIds: participantIds,
		Threshold:      threshold,
		Limit:          limit,
	}, nil
}
