package one_round_frost

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/ted25519/frost"
)

var testCurve = curves.ED25519()

// prepareDkgOutput creates two DKG participants
func prepareDkgOutput(t *testing.T) (*dkg.DkgParticipant, *dkg.DkgParticipant) {
	t.Helper()
	// Initiate two participants and running DKG round 1
	p1, err := dkg.NewDkgParticipant(1, 2, testCurve, []uint32{1, 2})
	require.NoError(t, err)
	p2, err := dkg.NewDkgParticipant(2, 2, testCurve, []uint32{1, 2})
	require.NoError(t, err)

	// FROST DKG Round 1 - Commit
	commitment1, _ := p1.Round1Commit()
	commitment2, _ := p2.Round1Commit()

	// FROST DKG Round 2 - Open
	commitments := make(map[uint32]*core.Commitment, 2)
	commitments[p1.Id] = commitment1
	commitments[p2.Id] = commitment2
	opening1, _ := p1.Round2Open(commitments)
	opening2, _ := p2.Round2Open(commitments)
	openings := make(map[uint32]*core.Witness, 2)
	openings[p1.Id] = opening1
	openings[p2.Id] = opening2

	// FROST DKG Round 3
	bcast1, p2psend1, err := p1.Round3FrostDkgFirstRound(nil, openings)
	require.NoError(t, err)
	bcast2, p2psend2, err := p2.Round3FrostDkgFirstRound(nil, openings)
	require.NoError(t, err)

	// FROST DKG Round 4
	bcast := make(map[uint32]*dkg.Round3Bcast)
	p2p1 := make(map[uint32]*sharing.ShamirShare)
	p2p2 := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p1[2] = p2psend2[1]
	p2p2[1] = p2psend1[2]
	_, _ = p1.Round4FrostDkgSecondRound(bcast, p2p1)
	_, _ = p2.Round4FrostDkgSecondRound(bcast, p2p2)
	return p1, p2
}

// TestSignerCommitWorks tests signer's Commit method
func TestSignerCommitWorks(t *testing.T) {
	signatureCountBound := uint32(3)
	p1, p2 := prepareDkgOutput(t)
	require.NotNil(t, p1)
	require.NotNil(t, p2)
	signer1, err := NewSigner(p1, []uint32{p1.Id, p2.Id}, frost.DeriveChallenge)
	require.NoError(t, err)

	signingCommitment, err := signer1.CommitInPreprocessingPhase(signatureCountBound)
	require.NoError(t, err)
	require.Equal(t, uint32(len(signingCommitment)), signatureCountBound)
	require.Equal(t, uint32(len(signer1.smallEs)), signatureCountBound)
	require.Equal(t, uint32(len(signer1.smallDs)), signatureCountBound)
	for _, commitment := range signingCommitment {
		require.NotNil(t, commitment.capDi)
		require.NotNil(t, commitment.capEi)
	}
	for _, e := range signer1.smallEs {
		require.NotNil(t, e)
	}
	for _, d := range signer1.smallDs {
		require.NotNil(t, d)
	}

	// Test wrong case if signatureCountBound = 0
	signer1, _ = NewSigner(p1, []uint32{p1.Id, p2.Id}, frost.DeriveChallenge)
	_, err = signer1.CommitInPreprocessingPhase(0)
	require.Error(t, err)
}

// prepareNewSignerAndCoordinator prepares new signers and create a coordinator.
// This is the complete one-time preprocessing phase specified for 2-2 case.
func prepareNewSignerAndCoordinator(t *testing.T, signatureCountBound uint32) (*Signer, *Signer, *Coordinator) {
	t.Helper()
	threshold := uint32(2)
	limit := uint32(2)
	p1, p2 := prepareDkgOutput(t)
	require.Equal(t, p1.VerificationKey, p2.VerificationKey)
	signer1, err := NewSigner(p1, []uint32{p1.Id, p2.Id}, frost.DeriveChallenge)
	require.NotNil(t, signer1)
	require.NoError(t, err)
	signer2, err := NewSigner(p2, []uint32{p1.Id, p2.Id}, frost.DeriveChallenge)
	require.NotNil(t, signer2)
	require.NoError(t, err)
	signingCommitment1, _ := signer1.CommitInPreprocessingPhase(signatureCountBound)
	signingCommitment2, _ := signer2.CommitInPreprocessingPhase(signatureCountBound)
	commitmentBundle := make(map[uint32][]*SigningCommitment, threshold)
	commitmentBundle[signer1.id] = signingCommitment1
	commitmentBundle[signer2.id] = signingCommitment2
	coordinator, err := NewCoordinator(p1.VerificationKey, testCurve, threshold, limit, frost.DeriveChallenge, commitmentBundle, signatureCountBound)
	require.NoError(t, err)
	require.NotNil(t, coordinator)
	return signer1, signer2, coordinator
}

// TestDistributeCommitmentsMultipleTimes tests coordinator's DistributeCommitment method
// we can change the signatureCountBound number and test any number of times.
func TestDistributeCommitmentsMultipleTimes(t *testing.T) {
	threshold := uint32(2)
	signatureCountBound := uint32(50) // we can change this bound number to 100, 1000, 10000... to test
	_, _, coordinator := prepareNewSignerAndCoordinator(t, signatureCountBound)
	for i := uint32(1); i <= signatureCountBound; i++ {
		outputCommitments, err := coordinator.DistributeCommitments()
		require.NoError(t, err)
		require.NotNil(t, outputCommitments)
		require.Equal(t, uint32(len(outputCommitments)), threshold)
	}
	// repeat call, since we have run out of 50 commitment pairs for each signer, this should throw error
	_, err := coordinator.DistributeCommitments()
	require.Error(t, err)
}

// TestSignMultipleTimes tests signer's Sign method
// we can change the signatureCountBound number and test any number of times.
func TestSignMultipleTimes(t *testing.T) {
	signatureCountBound := uint32(50) // we can change the bound number to 100, 1000, 10000 ... to test
	// Preprocessing
	signer1, _, coordinator := prepareNewSignerAndCoordinator(t, signatureCountBound)
	msg := []byte("message")
	// Run 50 rounds
	var lastCommitments map[uint32]*SigningCommitment
	for i := uint32(1); i <= signatureCountBound; i++ {
		outputCommitments, _ := coordinator.DistributeCommitments()
		lastCommitments = outputCommitments
		signatureShare, err := signer1.Sign(msg, outputCommitments)
		require.NoError(t, err)
		require.NotNil(t, signatureShare)
		require.NotNil(t, signatureShare.zi)
		require.Equal(t, signer1.msg, msg)
		require.Equal(t, uint32(len(coordinator.commitments[signer1.id])), signatureCountBound-i)
		require.Equal(t, uint32(len(signer1.smallDs)), signatureCountBound-i)
		require.Equal(t, uint32(len(signer1.smallEs)), signatureCountBound-i)
	}
	// Try one more repeated call, it should be error since the signer has
	// run out of stored nonces.
	_, err := signer1.Sign(msg, lastCommitments)
	require.Error(t, err)
}

// TestSignBadInput tests several wrong cases for signer's Sign method.
func TestSignBadInput(t *testing.T) {
	signatureCountBound := uint32(1)
	// Preparing outputCommitments
	signer1, _, coordinator := prepareNewSignerAndCoordinator(t, signatureCountBound)
	outputCommitments, _ := coordinator.DistributeCommitments()
	msg := []byte("message")

	// Actual Test: Set one of input commitment pairs to nil
	outputCommitments[signer1.id] = nil
	_, err := signer1.Sign(msg, outputCommitments)
	require.Error(t, err)

	// Preparing outputCommitments
	signer1, _, coordinator = prepareNewSignerAndCoordinator(t, signatureCountBound)
	outputCommitments, _ = coordinator.DistributeCommitments()
	// Actual Test: nil message
	_, err = signer1.Sign(nil, outputCommitments)
	require.Error(t, err)

	// Preparing outputCommitments
	signer1, signer2, coordinator := prepareNewSignerAndCoordinator(t, signatureCountBound)
	outputCommitments, _ = coordinator.DistributeCommitments()
	// Actual Test: invalid outputCommitments length
	testCommitments := make(map[uint32]*SigningCommitment, 3)
	testCommitments[signer1.id] = outputCommitments[signer1.id]
	testCommitments[signer2.id] = outputCommitments[signer2.id]
	testCommitments[3] = outputCommitments[signer2.id]
	_, err = signer1.Sign(msg, testCommitments)
	require.Error(t, err)

	// Preparing outputCommitments
	signer1, _, coordinator = prepareNewSignerAndCoordinator(t, signatureCountBound)
	outputCommitments, _ = coordinator.DistributeCommitments()
	// Actual Test: maul value of outputCommitments
	capEi := outputCommitments[signer1.id].capEi
	outputCommitments[signer1.id].capEi = capEi.Add(capEi)
	_, err = signer1.Sign(msg, outputCommitments)
	require.Error(t, err)
}

// Test coordinator's Aggregate and the verify method
// You can change the signatureCountBound number and test the process multiple times.
func TestSignatureAggregateAndVerifyMultipleTimes(t *testing.T) {
	// Preprocessing
	signatureCountBound := uint32(50) // we can test any times by changing the bound
	signer1, signer2, coordinator := prepareNewSignerAndCoordinator(t, signatureCountBound)
	msg := []byte("message")
	// Run 50 rounds after preprocessing
	for i := uint32(1); i <= signatureCountBound; i++ {
		outputCommitments, _ := coordinator.DistributeCommitments()
		signatureShare1, _ := signer1.Sign(msg, outputCommitments)
		signatureShare2, _ := signer2.Sign(msg, outputCommitments)
		signatureShares := make(map[uint32]*SignatureShare)
		signatureShares[signer1.id] = signatureShare1
		signatureShares[signer2.id] = signatureShare2
		capR := signer1.capR
		signature, err := coordinator.Aggregate(capR, signatureShares, msg)
		require.NoError(t, err)
		require.NotNil(t, signature.capR)
		require.NotNil(t, signature.z)

		// Verify the signature
		vk := signer1.verificationKey
		ok, err := Verify(testCurve, vk, msg, signature)
		require.NoError(t, err)
		require.True(t, ok)
	}
}

// Test the full one-round FROST process for (2,3) case.
// You can change the signatureCountBound number to test multiple rounds.
// That is, after DKG and one-time preprocessing, running one-round signing phase multiple times
func TestFullMultipleTimes(t *testing.T) {
	// Given a full one-round FROST test for (2,3) case
	threshold := uint32(2)
	limit := uint32(3)
	signatureCountBound := uint32(50) // we can test 100, 1000, 10000...times

	// Prepare DKG participants
	participants := make(map[uint32]*dkg.DkgParticipant, limit)
	for i := uint32(1); i <= limit; i++ {
		participantIds := make([]uint32, limit)
		for j := 0; j < int(limit); j++ {
			participantIds[j] = uint32(j + 1)
		}
		p, err := dkg.NewDkgParticipant(i, threshold, testCurve, participantIds)
		require.NoError(t, err)
		participants[i] = p
	}

	// Prepare the fixed string used to prevent replay attack
	// Commit
	commitments := make(map[uint32]*core.Commitment, limit)
	for _, participant := range participants {
		commitment, err := participant.Round1Commit()
		require.NoError(t, err)
		commitments[participant.Id] = commitment
	}

	// Open
	openings := make(map[uint32]*core.Witness, limit)
	for _, participant := range participants {
		opening, err := participant.Round2Open(commitments)
		require.NoError(t, err)
		openings[participant.Id] = opening
	}

	// FROST DKG round 3
	rnd3Bcast := make(map[uint32]*dkg.Round3Bcast, len(participants))
	rnd3P2p := make(map[uint32]dkg.Round3P2PSend, len(participants))
	for id, p := range participants {
		bcast, p2psend, err := p.Round3FrostDkgFirstRound(nil, openings)
		require.NoError(t, err)
		rnd3Bcast[id] = bcast
		rnd3P2p[id] = p2psend
	}

	// FROST DKG round 4
	for id := range rnd3Bcast {
		rnd1P2pForP := make(map[uint32]*sharing.ShamirShare)
		for jid := range rnd3P2p {
			if jid == id {
				continue
			}
			rnd1P2pForP[jid] = rnd3P2p[jid][id]
		}
		_, err := participants[id].Round4FrostDkgSecondRound(rnd3Bcast, rnd1P2pForP)
		require.NoError(t, err)
	}

	// Here we use {1, 3} as 2 of 3 cosigners, we can also set cosigners as {1, 2}, {2, 3}
	signerIds := []uint32{1, 3}
	signers := make(map[uint32]*Signer, threshold)
	var err error
	for _, id := range signerIds {
		signers[id], err = NewSigner(participants[id], signerIds, frost.DeriveChallenge)
		require.NoError(t, err)
		require.NotNil(t, signers[id].skShare)
	}

	// One-time Preprocessing
	vk := signers[1].verificationKey
	commitmentBundle := make(map[uint32][]*SigningCommitment, threshold)
	for id := range signers {
		signingCommitment, err := signers[id].CommitInPreprocessingPhase(signatureCountBound)
		require.NoError(t, err)
		commitmentBundle[signers[id].id] = signingCommitment
	}
	coordinator, _ := NewCoordinator(vk, testCurve, threshold, limit, frost.DeriveChallenge, commitmentBundle, signatureCountBound)

	// Running bound number of multiple rounds
	msg := []byte("message")
	for i := uint32(1); i <= signatureCountBound; i++ {
		// Signing round
		outputCommitments, err := coordinator.DistributeCommitments()
		require.NoError(t, err)
		signatureShares := make(map[uint32]*SignatureShare, threshold)
		for id := range signers {
			signatureShare, err := signers[id].Sign(msg, outputCommitments)
			require.NoError(t, err)
			signatureShares[signers[id].id] = signatureShare
		}

		// Coordinator aggregate signature shares
		capR := signers[1].capR
		signature, err := coordinator.Aggregate(capR, signatureShares, msg)
		require.NoError(t, err)
		require.NotNil(t, signature.z)
		require.NotNil(t, signature.capR)

		// Verify the signature
		ok, err := Verify(testCurve, vk, msg, signature)
		require.NoError(t, err)
		require.True(t, ok)
	}
}
