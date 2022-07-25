package common

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func Test_ProofSpecificMessageBlindingFactorIsIdempotent(t *testing.T) {
	t.Parallel()
	curve := curves.BLS12381(&curves.PointBls12381G2{})

	message := &ProofSpecificMessage{Message: curve.Scalar.Hash([]byte("something"))}
	blinding_1 := message.GetBlinding(rand.Reader)
	require.False(t, blinding_1.IsZero())
	require.False(t, blinding_1.IsOne())
	blinding_2 := message.GetBlinding(rand.Reader)
	require.NotEqual(t, blinding_1.Cmp(blinding_2), 0)
}
