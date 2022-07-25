package dealer_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dealer"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/sign"
)

func Test_DealerCanGenerateKeysThatSign(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		aliceOutput, bobOutput, err := dealer.GenerateAndDeal(curve)
		require.NoError(t, err)

		runTestSigning(t, curve, aliceOutput, bobOutput)
	}
}

func Test_DealerGeneratesDifferentResultsEachTime(t *testing.T) {
	curve := curves.K256()
	aliceOutput1, bobOutput1, err := dealer.GenerateAndDeal(curve)
	require.NoError(t, err)
	aliceOutput2, bobOutput2, err := dealer.GenerateAndDeal(curve)
	require.NoError(t, err)

	require.NotEqual(t, aliceOutput1.SecretKeyShare, aliceOutput2.SecretKeyShare)
	require.NotEqual(t, bobOutput1.SecretKeyShare, bobOutput2.SecretKeyShare)
	require.NotEqualValues(t, aliceOutput1.SeedOtResult.RandomChoiceBits, aliceOutput2.SeedOtResult.RandomChoiceBits)
	require.NotEqualValues(t, bobOutput1.SeedOtResult.OneTimePadEncryptionKeys, bobOutput2.SeedOtResult.OneTimePadEncryptionKeys)
}

func Test_DealerCanSplitExisitingPrivateKeysThatCanSign(t *testing.T) {
	tests := []struct {
		name          string
		privateKeyHex string
		curve         *curves.Curve
	}{
		// These private keys were generated randomly one time and hardcoded for deterministic tests
		// They were generated using the following code snippet:
		//
		// hex.EncodeToString(curves.K256().Scalar.Random(rand.Reader).Bytes()) (using the appropriate curve)
		{
			name:          "K256 curve",
			privateKeyHex: "73902defa578d2de559f8c8bc053d01fcd6bfeffc4596569f3ad77118542069a",
			curve:         curves.K256(),
		},
		{
			name:          "P256 curve",
			privateKeyHex: "517a0566fe7982f5db75e9b3362287b4d7447b1db2bb0d87f2f53e652e9668ba",
			curve:         curves.P256(),
		},
		{
			name:          "K256 curve with random private key",
			privateKeyHex: hex.EncodeToString(curves.K256().Scalar.Random(rand.Reader).Bytes()),
			curve:         curves.K256(),
		},
		{
			name:          "P256 curve with random private key",
			privateKeyHex: hex.EncodeToString(curves.P256().Scalar.Random(rand.Reader).Bytes()),
			curve:         curves.P256(),
		},
	}

	for _, test := range tests {
		boundTest := test
		t.Run(boundTest.name, func(t *testing.T) {
			privateKeyBytes, err := hex.DecodeString(boundTest.privateKeyHex)
			require.NoError(t, err)
			privateKeyScalar, err := boundTest.curve.Scalar.SetBytes(privateKeyBytes)
			require.NoError(t, err)

			aliceOutput, bobOutput, err := dealer.SplitAndDeal(boundTest.curve, privateKeyScalar)
			require.NoError(t, err)
			require.False(t, aliceOutput.SecretKeyShare.IsZero())
			require.False(t, aliceOutput.SecretKeyShare.IsOne())
			require.False(t, bobOutput.SecretKeyShare.IsZero())
			require.False(t, bobOutput.SecretKeyShare.IsOne())

			// Note: bob.Round4Final(...) will do an ecdsa.Verify check with the computed
			// signature and public key given in bobOutput
			runTestSigning(t, boundTest.curve, aliceOutput, bobOutput)
		})
	}
}

func runTestSigning(t *testing.T, curve *curves.Curve, aliceOutput *dkg.AliceOutput, bobOutput *dkg.BobOutput) {
	t.Helper()

	alice := sign.NewAlice(curve, sha3.New256(), aliceOutput)
	bob := sign.NewBob(curve, sha3.New256(), bobOutput)

	message := []byte("A message.")
	seed, err := alice.Round1GenerateRandomSeed()
	require.NoError(t, err)
	round3Output, err := bob.Round2Initialize(seed)
	require.NoError(t, err)
	round4Output, err := alice.Round3Sign(message, round3Output)
	require.NoError(t, err)
	err = bob.Round4Final(message, round4Output)
	require.NoError(t, err, "curve: %s", curve.Name)
}
