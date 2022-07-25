//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"crypto/sha512"
	"flag"
	"fmt"

	"filippo.io/edwards25519"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/ted25519/frost"
)

const (
	LIMIT     = 4
	THRESHOLD = 2
)

func main() {
	var threshold int
	var limit int
	var help bool
	flag.IntVar(&threshold, "t", THRESHOLD, "the minimum number of participants to sign")
	flag.IntVar(&threshold, "threshold", THRESHOLD, "the minimum number of participants to sign")
	flag.IntVar(&limit, "n", LIMIT, "the total number of participants")
	flag.IntVar(&limit, "limit", LIMIT, "the total number of participants")
	flag.BoolVar(&help, "h", false, "Print this menu")
	flag.BoolVar(&help, "help", false, "Print this menu")
	flag.Parse()

	if help {
		printHelp()
		return
	}

	fmt.Printf("Threshold is %d\n", threshold)
	fmt.Printf("Total participants is %d\n", limit)

	// DEMO doing FROST DKG and that signers can compute a signature
	// create dkg participants and running FROST DKG round 1 and round 2
	participants, openings := createDkgParticipantsAndPrepareOpenings(threshold, limit)

	// FROST DKG Round 3
	rnd3Bcast, rnd3P2p := dkgRound3(participants, openings)

	// FROST DKG Round 4
	verificationKey, signingShares := dkgRound4(participants, rnd3Bcast, rnd3P2p)

	// Signing common setup for all participants
	msg := []byte("All my bitcoin is stored here")
	curve := curves.ED25519()
	scheme, _ := sharing.NewShamir(uint32(threshold), uint32(limit), curve)
	shares := make([]*sharing.ShamirShare, 0, threshold)
	cnt := 0
	for _, share := range signingShares {
		if cnt == threshold {
			break
		}
		cnt++
		shares = append(shares, share)
	}
	sk, err := scheme.Combine(shares...)
	if err != nil {
		panic(err)
	}
	vk := curve.ScalarBaseMult(sk)
	if !vk.Equal(verificationKey) {
		panic("verification keys are not equal")
	}

	skC := sk.(*curves.ScalarEd25519).GetEdwardsScalar()

	r, s := sign(skC, vk.ToAffineCompressed(), []byte("no nonce"), msg)
	ok := verify(vk.ToAffineCompressed(), msg, r, s)
	fmt.Printf("Signature verification - %v\n", ok)

	// Test threshold signing
	lCoeffs, err := scheme.LagrangeCoeffs([]uint32{signingShares[1].Id, signingShares[2].Id})
	if err != nil {
		panic(err)
	}
	signers := make(map[uint32]*frost.Signer, 2)
	signers[1], err = frost.NewSigner(participants[1], 1, uint32(threshold), lCoeffs, []uint32{1, 2}, frost.DeriveChallenge)
	if err != nil {
		panic(err)
	}
	signers[2], err = frost.NewSigner(participants[2], 2, uint32(threshold), lCoeffs, []uint32{1, 2}, frost.DeriveChallenge)
	if err != nil {
		panic(err)
	}

	sigrnd1Bcast := make(map[uint32]*frost.Round1Bcast, 2)
	sigrnd1Bcast[1], err = signers[1].SignRound1()
	if err != nil {
		panic(err)
	}
	sigrnd1Bcast[2], err = signers[2].SignRound1()
	if err != nil {
		panic(err)
	}
	sigRnd2BCast := make(map[uint32]*frost.Round2Bcast, 2)
	sigRnd2BCast[1], err = signers[1].SignRound2(msg, sigrnd1Bcast)
	if err != nil {
		panic(err)
	}
	sigRnd2BCast[2], err = signers[2].SignRound2(msg, sigrnd1Bcast)
	if err != nil {
		panic(err)
	}
	sigRnd3BCast, err := signers[1].SignRound3(sigRnd2BCast)
	if err != nil {
		panic(err)
	}

	sigR := sigRnd3BCast.R.(*curves.PointEd25519).GetEdwardsPoint()
	sigS := sigRnd3BCast.Z.(*curves.ScalarEd25519).GetEdwardsScalar()

	ok = verify(vk.ToAffineCompressed(), msg, sigR, sigS)
	fmt.Printf("Threshold Signature verification - %v\n", ok)
}

func sign(skC *edwards25519.Scalar, pubKey, nonce, msg []byte) (*edwards25519.Point, *edwards25519.Scalar) {
	h := sha512.New()
	_, _ = h.Write(nonce)
	_, _ = h.Write(msg)
	digest := h.Sum(nil)
	digestReduced, err := edwards25519.NewScalar().SetUniformBytes(digest)
	if err != nil {
		panic(err)
	}
	r := edwards25519.NewGeneratorPoint().ScalarBaseMult(digestReduced)

	encodedR := r.Bytes()
	h.Reset()
	_, _ = h.Write(encodedR)
	_, _ = h.Write(pubKey)
	_, _ = h.Write(msg)

	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	s := edwards25519.NewScalar().MultiplyAdd(k, skC, digestReduced)
	return r, s
}

func verify(pk, msg []byte, r *edwards25519.Point, s *edwards25519.Scalar) bool {
	h := sha512.New()
	_, _ = h.Write(r.Bytes())
	_, _ = h.Write(pk)
	_, _ = h.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	minusA, _ := edwards25519.NewIdentityPoint().SetBytes(pk)
	minusA.Negate(minusA)
	lhs := edwards25519.NewIdentityPoint().VarTimeDoubleScalarBaseMult(k, minusA, s)
	return lhs.Equal(r) == 1
}

// createDkgParticipantsAndPrepareOpenings creates all dkg participants and running frost dkg round 1 and round 2.
func createDkgParticipantsAndPrepareOpenings(thresh, limit int) (map[uint32]*dkg.DkgParticipant, map[uint32]*core.Witness) {
	curve := curves.ED25519()
	// Prepare DKG participants
	participants := make(map[uint32]*dkg.DkgParticipant, limit)
	for i := 1; i <= limit; i++ {
		participantIds := make([]uint32, limit)
		for j := 0; j < limit; j++ {
			participantIds[j] = uint32(j + 1)
		}
		p, err := dkg.NewDkgParticipant(uint32(i), uint32(thresh), curve, participantIds)
		if err != nil {
			panic(err)
		}

		participants[uint32(i)] = p
	}

	// Prepare the fixed string used to prevent replay attack
	// Commit
	commitments := make(map[uint32]*core.Commitment, limit)
	for _, participant := range participants {
		commitment, err := participant.Round1Commit()
		if err != nil {
			panic(err)
		}
		commitments[participant.Id] = commitment
	}

	// Open
	openings := make(map[uint32]*core.Witness, limit)
	for _, participant := range participants {
		opening, err := participant.Round2Open(commitments)
		if err != nil {
			panic(err)
		}
		openings[participant.Id] = opening
	}

	return participants, openings
}

func dkgRound3(participants map[uint32]*dkg.DkgParticipant, openings map[uint32]*core.Witness) (map[uint32]*dkg.Round3Bcast, map[uint32]dkg.Round3P2PSend) {
	// DKG Round 1
	rnd3Bcast := make(map[uint32]*dkg.Round3Bcast, len(participants))
	rnd3P2p := make(map[uint32]dkg.Round3P2PSend, len(participants))
	for id, p := range participants {
		fmt.Printf("Computing FROST DKG Round 3 for participant %d\n", id)
		bcast, p2psend, err := p.Round3FrostDkgFirstRound(nil, openings)
		if err != nil {
			panic(err)
		}
		rnd3Bcast[id] = bcast
		rnd3P2p[id] = p2psend
	}
	return rnd3Bcast, rnd3P2p
}

func dkgRound4(participants map[uint32]*dkg.DkgParticipant,
	rnd3Bcast map[uint32]*dkg.Round3Bcast,
	rnd3P2p map[uint32]dkg.Round3P2PSend,
) (curves.Point, map[uint32]*sharing.ShamirShare) {
	signingShares := make(map[uint32]*sharing.ShamirShare, len(participants))
	var verificationKey curves.Point
	for id := range rnd3Bcast {
		fmt.Printf("Computing DKG Round 2 for participant %d\n", id)
		rnd3P2pForP := make(map[uint32]*sharing.ShamirShare)
		for jid := range rnd3P2p {
			if jid == id {
				continue
			}
			rnd3P2pForP[jid] = rnd3P2p[jid][id]
		}
		rnd4Out, err := participants[id].Round4FrostDkgSecondRound(rnd3Bcast, rnd3P2pForP)
		if err != nil {
			panic(err)
		}
		verificationKey = rnd4Out.VerificationKey
		share := &sharing.ShamirShare{
			Id:    id,
			Value: participants[id].SkShare.Bytes(),
		}
		signingShares[id] = share
	}
	return verificationKey, signingShares
}

func printHelp() {
	fmt.Printf(`
ed25519 INPUT
Simulate a DKG using Ed25519 keys
FLAGS:
  -h, --help						Show this help message and exit
  -n, --limit						The total number of participants
  -t, --treshold					The minimum number of participants needed to sign
`)
}
