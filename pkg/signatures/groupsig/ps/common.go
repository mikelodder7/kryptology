package ps

import (
	"github.com/gtank/merlin"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

// ensure interface compliance.
var (
	_ groupsig.SecretKey           = (*SecretKey)(nil)
	_ groupsig.PublicKey           = (*PublicKey)(nil)
	_ groupsig.Signature           = (*Signature)(nil)
	_ groupsig.BlindGroupSigner    = (*BlindSigner)(nil)
	_ groupsig.PokSignatureBuilder = (*PokSignatureBuilder)(nil)
	_ groupsig.PokSignature        = (*PokSignature)(nil)
)

func checkGivenPublicKeyForForgeryAttack(publicKey *PublicKey) error {
	if publicKey.XTilde.IsIdentity() {
		return errors.New("XTilde is at infinity")
	}
	if publicKey.YTildePrime.IsIdentity() {
		return errors.New("YTildePrime is at infinity")
	}
	for i, yTilde := range publicKey.YTildes {
		if yTilde.IsIdentity() {
			return errors.Errorf("%d'th y tilde is at infinity", i)
		}
	}
	return nil
}

func hashScalars(curve *curves.PairingCurve, xs []curves.Scalar) (curves.PairingScalar, error) {
	drbg := sha3.NewShake256()
	for _, x := range xs {
		if _, err := drbg.Write(x.Bytes()); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	randomBytes := make([]byte, 64)
	if _, err := drbg.Read(randomBytes); err != nil {
		return nil, errors.WithStack(err)
	}

	scalar, err := curve.Scalar.SetBytesWide(randomBytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	pairingScalar, ok := scalar.(curves.PairingScalar)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	return pairingScalar, nil
}

func writeToTranscript(randomCommitment, commitment []byte, transcript *merlin.Transcript) {
	transcript.AppendMessage([]byte("random commitment"), randomCommitment)
	transcript.AppendMessage([]byte("commitment"), commitment)
}
