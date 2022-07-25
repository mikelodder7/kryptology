package mina

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignatureMarshalBinary(t *testing.T) {
	_, sk, err := NewKeys()
	require.NoError(t, err)
	sig, err := sk.SignMessage("")
	require.NoError(t, err)
	blob, err := sig.MarshalBinary()
	require.NoError(t, err)
	sig2 := new(Signature)
	err = sig2.UnmarshalBinary(blob)
	require.NoError(t, err)
	require.Equal(t, sig, sig2)
	for i := range blob {
		blob[i] = 0
	}

	err = sig2.UnmarshalBinary(blob)
	require.Error(t, err)
	require.Equal(t, sig, sig2)
}
