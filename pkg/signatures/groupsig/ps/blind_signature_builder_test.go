package ps

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
)

func processBlindSignatureContext(t *testing.T, curve *curves.PairingCurve, allMessages []curves.Scalar, blindedMessages, knownMessages map[int]common.ProofMessage) (*Signature, *PublicKey) {
	t.Helper()
	secretKey, err := NewSecretKey(curve, len(allMessages))
	require.NoError(t, err)
	require.NotNil(t, secretKey)

	nonce := curve.Scalar.Random(rand.Reader)
	pk, ok := secretKey.PublicKey().(*PublicKey)
	require.True(t, ok)
	require.NotNil(t, pk)
	blindSignatureBuilder, blindingFactor, err := NewBlindSigner(pk, blindedMessages, nonce, rand.Reader)
	require.NoError(t, err)
	require.NotNil(t, blindingFactor)
	require.NotNil(t, blindSignatureBuilder)
	require.False(t, blindSignatureBuilder.commitment.IsIdentity())
	require.False(t, blindSignatureBuilder.challenge.IsZero())
	for _, p := range blindSignatureBuilder.proofs {
		require.False(t, p.IsZero())
	}

	blindSignature, err := blindSignatureBuilder.Sign(secretKey, knownMessages, nonce)
	require.NoError(t, err)

	psBlindSignature, ok := blindSignature.(*Signature)
	require.True(t, ok)

	err = Verify(psBlindSignature, pk, allMessages)
	require.Error(t, err)

	unblindedSignature, err := blindSignature.Unblind(blindingFactor)
	require.NoError(t, err)

	unblindedPSSignature, ok := unblindedSignature.(*Signature)
	require.True(t, ok)

	return unblindedPSSignature, pk
}

func TestBlindSignatureContext_Works(t *testing.T) {
	t.Parallel()
	curve := curves.BLS12381(&curves.PointBls12381G2{})

	allMessages := []curves.Scalar{
		curve.Scalar.Hash([]byte("firstname")),
		curve.Scalar.Hash([]byte("lastname")),
		curve.Scalar.Hash([]byte("age")),
		curve.Scalar.Hash([]byte("something else")),
	}

	for _, test := range []struct {
		name            string
		blindedMessages map[int]common.ProofMessage
		knownMessages   map[int]common.ProofMessage
	}{
		{
			name: "Happy path",
			blindedMessages: map[int]common.ProofMessage{
				1: common.ProofSpecificMessage{Message: allMessages[1]},
				3: common.ProofSpecificMessage{Message: allMessages[3]},
			},
			knownMessages: map[int]common.ProofMessage{
				0: common.RevealedMessage{Message: allMessages[0]},
				2: common.RevealedMessage{Message: allMessages[2]},
			},
		},
		{
			name: "Unsorted indices",
			blindedMessages: map[int]common.ProofMessage{
				3: common.ProofSpecificMessage{Message: allMessages[3]},
				1: common.ProofSpecificMessage{Message: allMessages[1]},
			},
			knownMessages: map[int]common.ProofMessage{
				2: common.RevealedMessage{Message: allMessages[2]},
				0: common.RevealedMessage{Message: allMessages[0]},
			},
		},
	} {
		rebindedTest := test
		t.Run(rebindedTest.name, func(tt *testing.T) {
			tt.Parallel()
			unblindedSignature, publicKey := processBlindSignatureContext(tt, curve, allMessages, rebindedTest.blindedMessages, rebindedTest.knownMessages)
			err := Verify(unblindedSignature, publicKey, allMessages)
			require.NoError(tt, err)
		})
	}
}

func TestBlindSignatureContext_DoNotWork(t *testing.T) {
	t.Parallel()
	curve := curves.BLS12381(&curves.PointBls12381G2{})

	allMessages := []curves.Scalar{
		curve.Scalar.Hash([]byte("firstname")),
		curve.Scalar.Hash([]byte("lastname")),
		curve.Scalar.Hash([]byte("age")),
		curve.Scalar.Hash([]byte("something else")),
	}

	for _, test := range []struct {
		name            string
		blindedMessages map[int]common.ProofMessage
		knownMessages   map[int]common.ProofMessage
	}{
		{
			name: "mismatched indices",
			blindedMessages: map[int]common.ProofMessage{
				1: common.ProofSpecificMessage{Message: allMessages[1]},
				3: common.ProofSpecificMessage{Message: allMessages[3]},
			},
			knownMessages: map[int]common.ProofMessage{
				0: common.RevealedMessage{Message: allMessages[0]},
				2: common.RevealedMessage{Message: allMessages[1]},
			},
		},
		{
			name: "bogus message",
			blindedMessages: map[int]common.ProofMessage{
				1: common.ProofSpecificMessage{Message: curve.Scalar.Hash([]byte("bogus"))},
				3: common.ProofSpecificMessage{Message: allMessages[3]},
			},
			knownMessages: map[int]common.ProofMessage{
				0: common.RevealedMessage{Message: allMessages[2]},
				2: common.RevealedMessage{Message: allMessages[0]},
			},
		},
	} {
		rebindedTest := test
		t.Run(rebindedTest.name, func(tt *testing.T) {
			tt.Parallel()
			unblindedSignature, publicKey := processBlindSignatureContext(tt, curve, allMessages, rebindedTest.blindedMessages, rebindedTest.knownMessages)
			err := Verify(unblindedSignature, publicKey, allMessages)
			require.Error(tt, err)
		})
	}
}
