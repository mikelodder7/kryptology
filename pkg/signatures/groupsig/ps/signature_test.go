package ps

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestSignatureWorks(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	messages := []curves.Scalar{
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
		curve.Scalar.New(6),
	}
	secretKey, err := NewSecretKey(curve, len(messages))
	require.NoError(t, err)

	signature, err := Sign(secretKey, messages)
	require.NoError(t, err)

	pk, ok := secretKey.PublicKey().(*PublicKey)
	require.True(t, ok)
	require.NotNil(t, pk)
	err = Verify(signature, pk, messages)
	require.NoError(t, err)
}

func TestSignatureIncorrectMessages(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	messages := []curves.Scalar{
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
		curve.Scalar.New(6),
	}
	secretKey, err := NewSecretKey(curve, len(messages))
	require.NoError(t, err)

	signature, err := Sign(secretKey, messages)
	require.NoError(t, err)
	pk, ok := secretKey.PublicKey().(*PublicKey)
	require.True(t, ok)
	require.NotNil(t, pk)
	messages[0] = curve.Scalar.New(0).(curves.PairingScalar)
	err = Verify(signature, pk, messages)
	require.Error(t, err)
}
