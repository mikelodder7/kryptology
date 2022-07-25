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
	bls "github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
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
	// create participants and running the FROST DKG first 2 rounds.
	participants, openings := createDkgParticipantsAndPrepareOpenings(threshold, limit)

	// FROST DKG Round 3
	rnd3Bcast, rnd3P2p := dkgRound3(participants, openings)

	// FROST DKG Round 4
	verificationKey, signingShares := dkgRound4(participants, rnd3Bcast, rnd3P2p)

	// Signing common setup for all participants
	scheme := bls.NewSigEth2()
	msg := []byte("All my bitcoin is stored here")

	// Signing
	partialSigs := make([]*bls.PartialSignature, 0, threshold)
	cnt := 0
	for id, sk := range signingShares {
		if cnt == threshold {
			break
		}
		cnt++
		fmt.Printf("Signing for participant %d\n", id)
		skShare := new(bls.SecretKeyShare)
		// secret share expects 1 byte identifier at the end of the array
		skBytes := make([]byte, bls.SecretKeyShareSize)
		copy(skBytes, sk[4:])
		skBytes[bls.SecretKeyShareSize-1] = sk[3]
		err := skShare.UnmarshalBinary(skBytes)
		if err != nil {
			panic(err)
		}
		sig, err := scheme.PartialSign(skShare, msg)
		if err != nil {
			panic(err)
		}
		partialSigs = append(partialSigs, sig)
	}
	if verificationKey == nil {
		panic("verification key was never complete")
	}

	sig, err := scheme.CombineSignatures(partialSigs...)
	if err != nil {
		panic(err)
	}

	pk := new(bls.PublicKey)
	err = pk.UnmarshalBinary(verificationKey.ToAffineCompressed())
	if err != nil {
		panic(err)
	}

	ok, err := scheme.Verify(pk, msg, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature verification - %v\n", ok)
}

// createDkgParticipantsAndPrepareOpenings creates DKG participants and running FROST DKG round 1 and 2.
func createDkgParticipantsAndPrepareOpenings(thresh, limit int) (map[uint32]*dkg.DkgParticipant, map[uint32]*core.Witness) {
	curve := curves.BLS12381G1()
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
) (curves.Point, map[uint32][]byte) {
	signingShares := make(map[uint32][]byte, len(participants))
	var verificationKey curves.Point
	for id := range rnd3Bcast {
		fmt.Printf("Computing FROST DKG Round 4 for participant %d\n", id)
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
		share := sharing.ShamirShare{
			Id:    id,
			Value: participants[id].SkShare.Bytes(),
		}
		signingShares[id] = share.Bytes()
	}
	return verificationKey, signingShares
}

func printHelp() {
	fmt.Printf(`
bls INPUT
Simulate a DKG using BLS keys
FLAGS:
  -h, --help						Show this help message and exit
  -n, --limit						The total number of participants
  -t, --treshold					The minimum number of participants needed to sign
`)
}
