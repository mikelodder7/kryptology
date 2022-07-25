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
	"github.com/coinbase/kryptology/pkg/signatures/schnorr/mina"
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
	participants, openings := createDkgParticipantsAndPrepareOpenings(threshold, limit)

	// DKG Round 1
	rnd3Bcast, rnd3P2p := dkgRound3(participants, openings)

	// DKG Round 2
	verificationKey, signingShares := dkgRound4(participants, rnd3Bcast, rnd3P2p)

	// Signing common setup for all participants
	curve := curves.PALLAS()
	scheme, _ := sharing.NewShamir(uint32(threshold), uint32(limit), curve)
	sk, err := scheme.Combine(signingShares[1], signingShares[2])
	if err != nil {
		panic(err)
	}
	skC := new(mina.SecretKey)
	skC.SetField(sk.(*curves.ScalarPallas).Value)
	vk := skC.GetPublicKey()
	pk := new(mina.PublicKey)
	pk.SetPointPallas(verificationKey.(*curves.PointPallas))
	if pk.GenerateAddress() != vk.GenerateAddress() {
		fmt.Printf("generated key is different than expected")
	}

	feePayerPk := new(mina.PublicKey)
	_ = feePayerPk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	sourcePk := new(mina.PublicKey)
	_ = sourcePk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	receiverPk := new(mina.PublicKey)
	_ = receiverPk.ParseAddress("B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy")
	txn := &mina.Transaction{
		Fee:        3,
		FeeToken:   1,
		Nonce:      200,
		ValidUntil: 10000,
		Memo:       "this is a memo",
		FeePayerPk: feePayerPk,
		SourcePk:   sourcePk,
		ReceiverPk: receiverPk,
		TokenId:    1,
		Amount:     42,
		Locked:     false,
		Tag:        [3]bool{false, false, false},
		NetworkId:  mina.MainNet,
	}
	sig, _ := skC.SignTransaction(txn)

	ok := vk.VerifyTransaction(sig, txn)
	fmt.Printf("Signature verification - %v\n", ok == nil)

	// Test threshold signing
	lcs, err := scheme.LagrangeCoeffs([]uint32{signingShares[1].Id, signingShares[2].Id})
	if err != nil {
		panic(err)
	}
	signers := make(map[uint32]*frost.Signer, 2)
	signers[1], err = frost.NewSigner(participants[1], 1, uint32(threshold), lcs, []uint32{1, 2}, frost.DeriveMinaChallenge)
	if err != nil {
		panic(err)
	}
	signers[2], err = frost.NewSigner(participants[2], 2, uint32(threshold), lcs, []uint32{1, 2}, frost.DeriveMinaChallenge)
	if err != nil {
		panic(err)
	}
	msg, _ := txn.MarshalBinary()

	sigRnd1Bcast := make(map[uint32]*frost.Round1Bcast, 2)
	sigRnd1Bcast[1], err = signers[1].SignRound1()
	if err != nil {
		panic(err)
	}
	sigRnd1Bcast[2], err = signers[2].SignRound1()
	if err != nil {
		panic(err)
	}
	sigRnd2BCast := make(map[uint32]*frost.Round2Bcast, 2)
	sigRnd2BCast[1], err = signers[1].SignRound2(msg, sigRnd1Bcast)
	if err != nil {
		panic(err)
	}
	sigRnd2BCast[2], err = signers[2].SignRound2(msg, sigRnd1Bcast)
	if err != nil {
		panic(err)
	}
	sigRnd3BCast, err := signers[1].SignRound3(sigRnd2BCast)
	if err != nil {
		panic(err)
	}

	secSig := &mina.Signature{
		R: sigRnd3BCast.R.(*curves.PointPallas).X(),
		S: sigRnd3BCast.Z.(*curves.ScalarPallas).Value,
	}

	ok = pk.VerifyTransaction(secSig, txn)
	fmt.Printf("Threshold Signature verification - %v\n", ok == nil)
	ok = vk.VerifyTransaction(secSig, txn)
	fmt.Printf("Threshold Signature verification - %v\n", ok == nil)
}

func dkgRound3(participants map[uint32]*dkg.DkgParticipant, openings map[uint32]*core.Witness) (map[uint32]*dkg.Round3Bcast, map[uint32]dkg.Round3P2PSend) {
	// DKG Round 3
	rnd1Bcast := make(map[uint32]*dkg.Round3Bcast, len(participants))
	rnd1P2p := make(map[uint32]dkg.Round3P2PSend, len(participants))
	for id, p := range participants {
		bcast, p2psend, err := p.Round3FrostDkgFirstRound(nil, openings)
		if err != nil {
			panic(err)
		}
		rnd1Bcast[id] = bcast
		rnd1P2p[id] = p2psend
	}
	return rnd1Bcast, rnd1P2p
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
		rnd2Out, err := participants[id].Round4FrostDkgSecondRound(rnd3Bcast, rnd1P2pForP)
		if err != nil {
			panic(err)
		}
		verificationKey = rnd2Out.VerificationKey
		share := &sharing.ShamirShare{
			Id:    id,
			Value: participants[id].SkShare.Bytes(),
		}
		signingShares[id] = share
	}
	return verificationKey, signingShares
}

func createDkgParticipantsAndPrepareOpenings(thresh, limit int) (map[uint32]*dkg.DkgParticipant, map[uint32]*core.Witness) {
	curve := curves.PALLAS()
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
mina INPUT
Simulate a DKG using Mina keys
FLAGS:
  -h, --help						Show this help message and exit
  -n, --limit						The total number of participants
  -t, --treshold					The minimum number of participants needed to sign
`)
}
