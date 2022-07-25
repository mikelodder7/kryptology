package ps

import (
	"crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
)

func getRevealedMessages(t *testing.T, proofMessages []common.ProofMessage) map[int]curves.Scalar {
	t.Helper()
	results := map[int]curves.Scalar{}
	for i, proofMessage := range proofMessages {
		if proofMessage.IsHidden() {
			continue
		}
		results[i] = proofMessage.GetMessage()
	}
	return results
}

func TestPokSignatureProofWorks(t *testing.T) {
	t.Parallel()

	curve := curves.BLS12381(&curves.PointBls12381G2{})
	messages := []curves.Scalar{
		curve.Scalar.New(2),
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
	}
	secretKey, err := NewSecretKey(curve, len(messages))
	require.NoError(t, err)

	signature, err := Sign(secretKey, messages)
	require.NoError(t, err)
	require.NotNil(t, signature)

	for _, test := range []struct {
		explanation   string
		proofMessages []common.ProofMessage
	}{
		{
			explanation: "some messages are revealed",
			proofMessages: []common.ProofMessage{
				&common.ProofSpecificMessage{
					Message: messages[0],
				},
				&common.ProofSpecificMessage{
					Message: messages[1],
				},
				&common.RevealedMessage{
					Message: messages[2],
				},
				&common.RevealedMessage{
					Message: messages[3],
				},
			},
		},
		{
			explanation: "all messages are revealed",
			proofMessages: []common.ProofMessage{
				&common.RevealedMessage{
					Message: messages[0],
				},
				&common.RevealedMessage{
					Message: messages[1],
				},
				&common.RevealedMessage{
					Message: messages[2],
				},
				&common.RevealedMessage{
					Message: messages[3],
				},
			},
		},
		{
			explanation: "all messages are hidden",
			proofMessages: []common.ProofMessage{
				&common.ProofSpecificMessage{
					Message: messages[0],
				},
				&common.ProofSpecificMessage{
					Message: messages[1],
				},
				&common.ProofSpecificMessage{
					Message: messages[2],
				},
				&common.ProofSpecificMessage{
					Message: messages[3],
				},
			},
		},
	} {
		boundedTest := test
		t.Run(boundedTest.explanation, func(t *testing.T) {
			t.Parallel()

			// Prover
			proverTranscript := merlin.NewTranscript("new ps pok signature")
			pk, ok := secretKey.PublicKey().(*PublicKey)
			require.True(t, ok)
			require.NotNil(t, pk)
			pok, err := NewComposablePokSignature(signature, pk, boundedTest.proofMessages, rand.Reader)
			require.NoError(t, err)
			require.NotNil(t, pok)
			require.False(t, pok.Proof.Sigma1Prime.IsIdentity())
			require.False(t, pok.Proof.Sigma2Prime.IsIdentity())
			require.False(t, pok.Proof.Commitment.IsIdentity())

			nonce := curve.Scalar.Random(rand.Reader)

			err = pok.WriteChallengeContribution(proverTranscript)
			require.NoError(t, err)
			proverTranscript.AppendMessage([]byte("nonce"), nonce.Bytes())
			okm := proverTranscript.ExtractBytes([]byte("signature proof of knowledge"), 64)
			challenge, err := curve.Scalar.SetBytesWide(okm)
			require.NoError(t, err)

			proof, err := pok.GenerateProof(challenge)
			require.NoError(t, err)

			psProof, ok := proof.(*PokSignature)
			require.True(t, ok)

			require.False(t, psProof.Sigma1Prime.IsIdentity())
			require.False(t, psProof.Sigma2Prime.IsIdentity())
			require.False(t, psProof.Commitment.IsIdentity())
			for _, p := range psProof.SchnorrProofs {
				require.False(t, p.IsZero())
			}

			// Verifier
			revealedMessages := getRevealedMessages(t, boundedTest.proofMessages)
			err = psProof.VerifySignatureProof(pk, revealedMessages)
			require.NoError(t, err)

			// manually verify schnorr proofs
			verifierTranscript := merlin.NewTranscript("new ps pok signature")
			err = psProof.WriteProofContribution(pk, challenge, revealedMessages, verifierTranscript)
			require.NoError(t, err)
			verifierTranscript.AppendMessage([]byte("nonce"), nonce.Bytes())
			verifierOkm := verifierTranscript.ExtractBytes([]byte("signature proof of knowledge"), 64)
			computedChallenge, err := curve.Scalar.SetBytesWide(verifierOkm)
			require.NoError(t, err)

			require.Equal(t, computedChallenge.Cmp(challenge), 0)
		})
	}
}

func TestPokSignatureBuilder(t *testing.T) {
	curve := curves.GetPairingCurveByName(curves.BLS12381G1Name)
	msgs := []curves.Scalar{
		curve.NewScalar().New(1),
		curve.NewScalar().New(2),
		curve.NewScalar().New(3),
		curve.NewScalar().New(4),
	}
	sk, err := NewSecretKey(curve, 4)
	require.NoError(t, err)
	require.NotNil(t, sk)

	sig, err := sk.Sign(msgs)
	require.NoError(t, err)
	psig, ok := sig.(*Signature)
	require.True(t, ok)

	pk, ok := sk.PublicKey().(*PublicKey)
	require.True(t, ok)
	proofMsgs := []common.ProofMessage{
		common.ProofSpecificMessage{Message: msgs[0]},
		common.ProofSpecificMessage{Message: msgs[1]},
		common.ProofSpecificMessage{Message: msgs[2]},
		common.ProofSpecificMessage{Message: msgs[3]},
	}
	revealedMsgs := make(map[int]curves.Scalar, 0)
	for i := 0; i < 4; i++ {
		builder, err := NewComposablePokSignature(psig, pk, proofMsgs, rand.Reader)
		require.NoError(t, err)
		transcript := merlin.NewTranscript("test")
		err = builder.WriteChallengeContribution(transcript)
		require.NoError(t, err)
		challenge := genChallenge(curve, transcript)
		proof, err := builder.GenerateProof(challenge)
		require.NoError(t, err)
		require.NotNil(t, proof)

		transcript = merlin.NewTranscript("test")
		err = proof.WriteProofContribution(pk, challenge, revealedMsgs, transcript)
		require.NoError(t, err)
		vChallenge := genChallenge(curve, transcript)
		require.Equal(t, 0, challenge.Cmp(vChallenge))

		proofMsgs[i] = common.RevealedMessage{Message: msgs[0]}
		revealedMsgs[i] = msgs[0]
	}
}

func genChallenge(curve *curves.PairingCurve, transcript *merlin.Transcript) curves.Scalar {
	chBytes := transcript.ExtractBytes([]byte("output"), 64)
	s, _ := curve.NewScalar().SetBytesWide(chBytes)
	return s
}
