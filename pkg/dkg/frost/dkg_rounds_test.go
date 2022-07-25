//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

var testCurve = curves.ED25519()

func CreateParticipantsAndGetOpenings(t *testing.T) (*DkgParticipant, *DkgParticipant, map[uint32]*core.Witness) {
	t.Helper()
	p1, err := NewDkgParticipant(1, 2, testCurve, []uint32{1, 2})
	require.NoError(t, err)
	p2, err := NewDkgParticipant(2, 2, testCurve, []uint32{1, 2})
	require.NoError(t, err)

	// Commit
	commitment1, _ := p1.Round1Commit()
	commitment2, _ := p2.Round1Commit()

	// Open
	commitments := make(map[uint32]*core.Commitment, 2)
	commitments[p1.Id] = commitment1
	commitments[p2.Id] = commitment2
	opening1, _ := p1.Round2Open(commitments)
	opening2, _ := p2.Round2Open(commitments)
	openings := make(map[uint32]*core.Witness, 2)
	openings[p1.Id] = opening1
	openings[p2.Id] = opening2
	return p1, p2, openings
}

// Test rounds for generating ctx
func TestCtxGenerationAndDkgRound1(t *testing.T) {
	p1, p2, openings := CreateParticipantsAndGetOpenings(t)
	// Dkg round 1
	bcast1, p2psend1, err := p1.Round3FrostDkgFirstRound(nil, openings)
	require.NoError(t, err)
	require.NotNil(t, bcast1)
	require.NotNil(t, p2psend1)
	require.NotNil(t, p1.ctx)
	require.Equal(t, len(p2psend1), 1)
	require.Equal(t, p1.round, 4)
	bcast2, p2psend2, err := p2.Round3FrostDkgFirstRound(nil, openings)
	require.NoError(t, err)
	require.NotNil(t, bcast2)
	require.NotNil(t, p2psend2)
	require.NotNil(t, p2.ctx)
	require.Equal(t, len(p2psend2), 1)
	require.Equal(t, p2.round, 4)
	require.True(t, bytes.Equal(p1.ctx, p2.ctx))
}

func TestDkgRound1RepeatCall(t *testing.T) {
	p1, _, openings := CreateParticipantsAndGetOpenings(t)
	// Repeat call
	_, _, err := p1.Round3FrostDkgFirstRound(nil, openings)
	require.NoError(t, err)
	_, _, err = p1.Round3FrostDkgFirstRound(nil, openings)
	require.Error(t, err)
}

func TestDkgRound3BadSecret(t *testing.T) {
	p1, _, openings := CreateParticipantsAndGetOpenings(t)
	// secret == 0
	secret := []byte{0}
	_, _, err := p1.Round3FrostDkgFirstRound(secret, openings)
	require.Error(t, err)
	// secret too big
	secret = []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}
	_, _, err = p1.Round3FrostDkgFirstRound(secret, openings)
	require.Error(t, err)
}

func PrepareRound4Input(t *testing.T) (*DkgParticipant, *DkgParticipant, *Round3Bcast, *Round3Bcast, Round3P2PSend, Round3P2PSend) {
	t.Helper()
	p1, p2, openings := CreateParticipantsAndGetOpenings(t)
	bcast1, p2psend1, _ := p1.Round3FrostDkgFirstRound(nil, openings)
	bcast2, p2psend2, _ := p2.Round3FrostDkgFirstRound(nil, openings)
	return p1, p2, bcast1, bcast2, p2psend1, p2psend2
}

// Test FROST DKG round 2 works
func TestDkgRound3Works(t *testing.T) {
	// Prepare Dkg Round1 output
	p1, _, bcast1, bcast2, _, p2psend2 := PrepareRound4Input(t)
	// Actual Test
	require.NotNil(t, bcast1)
	require.NotNil(t, bcast2)
	require.NotNil(t, p2psend2[1])
	bcast := make(map[uint32]*Round3Bcast)
	p2p := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	round2Out, err := p1.Round4FrostDkgSecondRound(bcast, p2p)
	require.NoError(t, err)
	require.NotNil(t, round2Out)
	require.NotNil(t, p1.SkShare)
	require.NotNil(t, p1.VkShare)
	require.NotNil(t, p1.VerificationKey)
}

// Test FROST DKG round 2 repeat call.
func TestDkgRound2RepeatCall(t *testing.T) {
	// Prepare round 1 output
	p1, _, bcast1, bcast2, _, p2psend2 := PrepareRound4Input(t)
	// Actual Test
	require.NotNil(t, bcast1)
	require.NotNil(t, bcast2)
	require.NotNil(t, p2psend2[1])
	bcast := make(map[uint32]*Round3Bcast)
	p2p := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	_, err := p1.Round4FrostDkgSecondRound(bcast, p2p)
	require.NoError(t, err)
	_, err = p1.Round4FrostDkgSecondRound(bcast, p2p)
	require.Error(t, err)
}

// Test FROST Dkg Round 2 Bad Input.
func TestDkgRound2BadInput(t *testing.T) {
	// Prepare Dkg Round 1 output
	p1, _, _, _, _, _ := PrepareRound4Input(t)
	bcast := make(map[uint32]*Round3Bcast)
	p2p := make(map[uint32]*sharing.ShamirShare)

	// Test empty bcast and p2p
	_, err := p1.Round4FrostDkgSecondRound(bcast, p2p)
	require.Error(t, err)

	// Test nil bcast and p2p
	p1, _, _, _, _, _ = PrepareRound4Input(t)
	_, err = p1.Round4FrostDkgSecondRound(nil, nil)
	require.Error(t, err)

	// Test tampered input bcast and p2p
	p1, _, bcast1, bcast2, _, p2psend2 := PrepareRound4Input(t)
	bcast = make(map[uint32]*Round3Bcast)
	p2p = make(map[uint32]*sharing.ShamirShare)

	// Tamper p2psend2 by doubling the value
	tmp, _ := testCurve.Scalar.SetBytes(p2psend2[1].Value)
	p2psend2[1].Value = tmp.Double().Bytes()
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	_, err = p1.Round4FrostDkgSecondRound(bcast, p2p)
	require.Error(t, err)
}

// Test full round works.
func TestFullDkgRoundsWorks(t *testing.T) {
	// Initiate two participants and running round 1
	p1, p2, bcast1, bcast2, p2psend1, p2psend2 := PrepareRound4Input(t)
	bcast := make(map[uint32]*Round3Bcast)
	p2p1 := make(map[uint32]*sharing.ShamirShare)
	p2p2 := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p1[2] = p2psend2[1]
	p2p2[1] = p2psend1[2]

	// Running round 2
	round2Out1, _ := p1.Round4FrostDkgSecondRound(bcast, p2p1)
	round2Out2, _ := p2.Round4FrostDkgSecondRound(bcast, p2p2)
	require.Equal(t, round2Out1.VerificationKey, round2Out2.VerificationKey)
	s, _ := sharing.NewShamir(2, 2, testCurve)
	sk, err := s.Combine(&sharing.ShamirShare{Id: p1.Id, Value: p1.SkShare.Bytes()},
		&sharing.ShamirShare{Id: p2.Id, Value: p2.SkShare.Bytes()})
	require.NoError(t, err)

	vk := testCurve.ScalarBaseMult(sk)
	require.True(t, vk.Equal(p1.VerificationKey))
}
