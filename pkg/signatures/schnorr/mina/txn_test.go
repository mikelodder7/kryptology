package mina

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTxnMarshaling(t *testing.T) {
	feePayerPk := new(PublicKey)
	err := feePayerPk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	sourcePk := new(PublicKey)
	err = sourcePk.ParseAddress("B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg")
	require.NoError(t, err)
	receiverPk := new(PublicKey)
	err = receiverPk.ParseAddress("B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy")
	require.NoError(t, err)
	txn := &Transaction{
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
		NetworkId:  MainNet,
	}

	blob, err := txn.MarshalBinary()
	require.NoError(t, err)
	txn2 := new(Transaction)
	err = txn2.UnmarshalBinary(blob)
	require.NoError(t, err)
	require.Equal(t, txn, txn2)
}
