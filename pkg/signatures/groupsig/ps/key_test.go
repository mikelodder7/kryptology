package ps

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestNewSecretKey(t *testing.T) {
	t.Parallel()
	curve := curves.GetPairingCurveByName(curves.BLS12381G2().Name)
	for _, test := range []struct {
		r   int
		err error
	}{
		{
			r:   -1,
			err: errors.New("r < 1"),
		},
		{
			r:   0,
			err: errors.New("r < 1"),
		},
		{
			r:   1,
			err: nil,
		},
		{
			r:   10,
			err: nil,
		},
	} {
		t.Run(fmt.Sprintf("testing keygen for r = %d", test.r), func(t *testing.T) {
			t.Parallel()
			secretKey, err := NewSecretKey(curve, test.r)
			if test.err != nil {
				require.EqualError(t, test.err, err.Error())
			} else {
				require.Len(t, secretKey.ys, test.r)
				require.NotNil(t, secretKey.yPrime)
			}
		})
	}
}

func TestKeyMarshal(t *testing.T) {
	curve := curves.GetPairingCurveByName(curves.BLS12381G2().Name)

	sk, err := NewSecretKey(curve, 10)
	require.NoError(t, err)
	require.NotNil(t, sk)

	skBytes, err := sk.MarshalBinary()
	require.NoError(t, err)
	// 384 for scalars, 145 metadata
	require.Equal(t, 529, len(skBytes))
	skDup := new(SecretKey)
	err = skDup.UnmarshalBinary(skBytes)
	require.NoError(t, err)
	require.Equal(t, 0, sk.x.Cmp(skDup.x))
	require.Equal(t, 0, sk.yPrime.Cmp(skDup.yPrime))
	for i, y := range sk.ys {
		require.Equal(t, 0, y.Cmp(skDup.ys[i]))
	}

	pkt := sk.PublicKey()
	require.NotNil(t, pkt)
	pk, ok := pkt.(*PublicKey)
	require.Equal(t, len(pk.YTildes), len(pk.Ys))
	require.True(t, ok)
	require.NotNil(t, pk)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)
	// 1632 = 1152 + 480 = (10+2)*96 + 10*48
	// 1899 = 1632 points, 267 metadata
	require.Equal(t, 1898, len(pkBytes))
	pkDup := new(PublicKey)
	err = pkDup.UnmarshalBinary(pkBytes)
	require.NoError(t, err)
	require.True(t, pk.XTilde.Equal(pkDup.XTilde))
	require.True(t, pk.YTildePrime.Equal(pkDup.YTildePrime))
	for i, y := range pk.Ys {
		require.True(t, y.Equal(pkDup.Ys[i]))
		require.True(t, pk.YTildes[i].Equal(pkDup.YTildes[i]))
	}
}
