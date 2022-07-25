//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"flag"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/ted25519/frost"
)

const (
	LIMIT     = 5
	THRESHOLD = 3
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
	// create all DKG participants and running frost dkg round 1 and 2.
	fmt.Printf("*Create participants and DKG Round 1 and 2")
	participants, openings := createDkgParticipantsAndPrepareOpenings(threshold, limit)

	// frost dkg round 3
	fmt.Printf("**FROST DKG Round 3**\n")
	rnd3Bcast, rnd3P2p := dkgRound3(participants, openings)

	// frost dkg round 4
	fmt.Printf("**FROST DKG Round 4**\n")
	verificationKey, _ := dkgRound4(participants, rnd3Bcast, rnd3P2p)

	// Prepare Lagrange coefficients
	curve := curves.ED25519()
	scheme, _ := sharing.NewShamir(uint32(threshold), uint32(limit), curve)
	shares := make([]*sharing.ShamirShare, threshold)
	for i := 0; i < threshold; i++ {
		shares[i] = &sharing.ShamirShare{Id: uint32(i + 1), Value: participants[uint32(i+1)].SkShare.Bytes()}
	}

	lCoeffs, err := scheme.LagrangeCoeffs([]uint32{shares[0].Id, shares[1].Id, shares[2].Id})
	if err != nil {
		panic(err)
	}

	// Using signer starting from 1 as cosigners
	signerIds := make([]uint32, threshold)
	for i := 0; i < threshold; i++ {
		signerIds[i] = uint32(i + 1)
	}
	signers := make(map[uint32]*frost.Signer, threshold)
	for i := 1; i <= threshold; i++ {
		signers[uint32(i)], err = frost.NewSigner(participants[uint32(i)], uint32(i), uint32(threshold), lCoeffs, signerIds, frost.DeriveChallenge)
		if err != nil {
			panic(err)
		}
	}

	// Running sign round 1
	fmt.Printf("**FROST Sign Round 1**\n")
	signRound2Input := make(map[uint32]*frost.Round1Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		fmt.Printf("Computing Sign Round 1 for cosigner %d\n", i)
		round1Out, err := signers[uint32(i)].SignRound1()
		if err != nil {
			panic(err)
		}
		signRound2Input[uint32(i)] = round1Out
	}

	// Running sign round 2
	fmt.Printf("**FROST Sign Round 2**\n")
	msg := []byte("message")
	signRound3Input := make(map[uint32]*frost.Round2Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		fmt.Printf("Computing Sign Round 2 for cosigner %d\n", i)
		signRound2Out, err := signers[uint32(i)].SignRound2(msg, signRound2Input)
		if err != nil {
			panic(err)
		}
		signRound3Input[uint32(i)] = signRound2Out
	}

	// Running sign round 3
	fmt.Printf("**FROST Sign Round 3**\n")
	result := make(map[uint32]*frost.Signature, threshold)
	for i := 1; i <= threshold; i++ {
		fmt.Printf("Computing Sign Round 3 for cosigner %d\n", i)
		signRound3Out, err := signers[uint32(i)].SignRound3(signRound3Input)
		if err != nil {
			panic(err)
		}
		result[uint32(i)] = signRound3Out
	}

	// Verify everybody's signature is valid
	for i := 1; i <= threshold; i++ {
		ok, _ := frost.Verify(curve, verificationKey, msg, result[uint32(i)])
		if !ok {
			panic(err)
		}
	}
	fmt.Printf("Signature is computed successfully!\n")
}

func dkgRound3(participants map[uint32]*dkg.DkgParticipant, openings map[uint32]*core.Witness) (map[uint32]*dkg.Round3Bcast, map[uint32]dkg.Round3P2PSend) {
	// FROST Dkg round 3
	rnd3Bcast := make(map[uint32]*dkg.Round3Bcast, len(participants))
	rnd3P2p := make(map[uint32]dkg.Round3P2PSend, len(participants))
	for id, p := range participants {
		fmt.Printf("Computing DKG Round 3 for participant %d\n", id)
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
		fmt.Printf("Computing DKG Round 4 for participant %d\n", id)
		rnd1P2pForP := make(map[uint32]*sharing.ShamirShare)
		for jid := range rnd3P2p {
			if jid == id {
				continue
			}
			rnd1P2pForP[jid] = rnd3P2p[jid][id]
		}
		rnd4Out, err := participants[id].Round4FrostDkgSecondRound(rnd3Bcast, rnd1P2pForP)
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

func printHelp() {
	fmt.Printf(`
bls INPUT
Simulate a DKG using K256 keys
FLAGS:
  -h, --help						Show this help message and exit
  -n, --limit						The total number of participants
  -t, --treshold					The minimum number of participants needed to sign
`)
}
