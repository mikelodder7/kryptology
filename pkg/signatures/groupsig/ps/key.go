package ps

import (
	"crypto/rand"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/groupsig"
)

type SecretKey struct {
	x, yPrime curves.PairingScalar // yPrime is y_{r+1} in the paper
	ys        []curves.PairingScalar
}

func (sk *SecretKey) MessageCount() int {
	return len(sk.ys)
}

func (*SecretKey) Type() groupsig.GroupSignatureScheme {
	return groupsig.PS
}

func (sk *SecretKey) Curve() (*curves.PairingCurve, error) {
	curve := curves.GetPairingCurveByName(sk.x.Point().CurveName())
	if curve == nil {
		return nil, errors.New("curve is nil")
	}
	return curve, nil
}

func (sk *SecretKey) PublicKey() groupsig.PublicKey {
	curve, err := sk.Curve()
	if err != nil {
		return nil
	}
	// For PublicKey
	// gTilde <- G*_2 but we use the G2 Basepoint instead of randomly getting a generator.
	// pk <- (gTilde, XTilde, YTilde_1, ... YTilde_r, YtildePrime)
	yTildes := make([]curves.PairingPoint, len(sk.ys))
	ys := make([]curves.PairingPoint, len(sk.ys))

	for i, y := range sk.ys {
		yTildes[i] = curve.ScalarG2BaseMult(y)
		ys[i] = curve.ScalarG1BaseMult(y)
	}

	return &PublicKey{
		XTilde:      curve.ScalarG2BaseMult(sk.x),
		YTildePrime: curve.ScalarG2BaseMult(sk.yPrime),
		YTildes:     yTildes,
		Ys:          ys,
	}
}

func (sk *SecretKey) Sign(messages []curves.Scalar) (groupsig.Signature, error) {
	return Sign(sk, messages)
}

func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	x, err := curves.ScalarMarshalBinary(sk.x)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	yPrime, err := curves.ScalarMarshalBinary(sk.yPrime)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ys := make([][]byte, len(sk.ys))
	for i, y := range sk.ys {
		yy, err := curves.ScalarMarshalBinary(y)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		ys[i] = yy
	}

	output := core.NewByteSerializer(uint(len(x) + len(yPrime) + len(ys)*len(x)))
	if _, err = output.WriteBytes(x); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = output.WriteBytes(yPrime); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = output.WriteByteArray(ys); err != nil {
		return nil, errors.WithStack(err)
	}

	return output.Bytes(), nil
}

func (sk *SecretKey) UnmarshalBinary(input []byte) error {
	reader := core.NewByteDeserializer(input)
	xBytes, err := reader.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	yPrimeBytes, err := reader.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	ysBytes, err := reader.ReadByteArray()
	if err != nil {
		return errors.WithStack(err)
	}

	x, err := unmarshalPairingScalar(xBytes)
	if err != nil {
		return errors.WithStack(err)
	}

	yPrime, err := unmarshalPairingScalar(yPrimeBytes)
	if err != nil {
		return errors.WithStack(err)
	}
	ys := make([]curves.PairingScalar, len(ysBytes))
	for i, y := range ysBytes {
		yy, err := unmarshalPairingScalar(y)
		if err != nil {
			return errors.WithStack(err)
		}
		ys[i] = yy
	}

	sk.x = x
	sk.yPrime = yPrime
	sk.ys = ys
	return nil
}

func unmarshalPairingScalar(input []byte) (curves.PairingScalar, error) {
	s, err := curves.ScalarUnmarshalBinary(input)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sc, ok := s.(curves.PairingScalar)
	if !ok {
		return nil, errors.New("invalid scalar")
	}
	return sc, nil
}

type PublicKey struct {
	XTilde, YTildePrime curves.PairingPoint
	YTildes             []curves.PairingPoint
	Ys                  []curves.PairingPoint
}

func (*PublicKey) Type() groupsig.GroupSignatureScheme {
	return groupsig.PS
}

func (pk *PublicKey) Curve() (*curves.PairingCurve, error) {
	curve := curves.GetPairingCurveByName(pk.XTilde.CurveName())
	if curve == nil {
		return nil, errors.New("curve is nil")
	}
	return curve, nil
}

func (pk *PublicKey) MessageCount() int {
	return len(pk.YTildes)
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	xTilde, err := curves.PointMarshalBinary(pk.XTilde)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	yTildePrime, err := curves.PointMarshalBinary(pk.YTildePrime)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	yTildes := make([][]byte, len(pk.YTildes))
	ys := make([][]byte, len(pk.Ys))
	for i, yTilde := range pk.YTildes {
		yt, err := curves.PointMarshalBinary(yTilde)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		yTildes[i] = yt

		y, err := curves.PointMarshalBinary(pk.Ys[i])
		if err != nil {
			return nil, errors.WithStack(err)
		}
		ys[i] = y
	}
	output := core.NewByteSerializer(uint(len(xTilde) + len(yTildePrime) + len(ys)*len(xTilde)*2))

	if _, err = output.WriteBytes(xTilde); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = output.WriteBytes(yTildePrime); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = output.WriteByteArray(yTildes); err != nil {
		return nil, errors.WithStack(err)
	}
	if _, err = output.WriteByteArray(ys); err != nil {
		return nil, errors.WithStack(err)
	}
	return output.Bytes(), nil
}

func (pk *PublicKey) UnmarshalBinary(input []byte) error {
	reader := core.NewByteDeserializer(input)
	xTildeBytes, err := reader.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	yTildePrimeBytes, err := reader.ReadBytes()
	if err != nil {
		return errors.WithStack(err)
	}
	yTildesBytes, err := reader.ReadByteArray()
	if err != nil {
		return errors.WithStack(err)
	}

	ysBytes, err := reader.ReadByteArray()
	if err != nil {
		return errors.WithStack(err)
	}

	xTilde, err := unMarshalPairingPoint(xTildeBytes)
	if err != nil {
		return errors.WithStack(err)
	}

	yTildePrime, err := unMarshalPairingPoint(yTildePrimeBytes)
	if err != nil {
		return errors.WithStack(err)
	}

	yTildes := make([]curves.PairingPoint, len(yTildesBytes))
	for i, yTildeBytes := range yTildesBytes {
		yTilde, err := unMarshalPairingPoint(yTildeBytes)
		if err != nil {
			return errors.WithStack(err)
		}
		yTildes[i] = yTilde
	}
	ys := make([]curves.PairingPoint, len(ysBytes))
	for i, yBytes := range ysBytes {
		y, err := unMarshalPairingPoint(yBytes)
		if err != nil {
			return errors.WithStack(err)
		}
		ys[i] = y
	}

	pk.XTilde = xTilde
	pk.YTildePrime = yTildePrime
	pk.YTildes = yTildes
	pk.Ys = ys
	return nil
}

func unMarshalPairingPoint(input []byte) (curves.PairingPoint, error) {
	pt, err := curves.PointUnmarshalBinary(input)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	ptt, ok := pt.(curves.PairingPoint)
	if !ok {
		return nil, errors.New("invalid point")
	}
	return ptt, nil
}

// NewSecretKey produces a secret key capable of producing a PS signature. It accepts a pairing curve, and
// an `r` which is the number of messages for which the key can produce a group signature.
func NewSecretKey(curve *curves.PairingCurve, r int) (*SecretKey, error) {
	// TODO: add an upper bound for r.
	if r < 1 {
		return nil, errors.New("r < 1")
	}
	// (x, y_1, ..., y_r, y') <- (Z*_p)^{r+2}
	x, ok := curve.Scalar.Random(rand.Reader).(curves.PairingScalar)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}
	// we need an aditional `y` for m'. This is due to https://eprint.iacr.org/2017/1197.pdf
	ys := make([]curves.PairingScalar, r)
	for i := 0; i < r; i++ {
		y, ok := curve.Scalar.Random(rand.Reader).(curves.PairingScalar)
		if !ok {
			return nil, errors.New("incorrect type conversion")
		}
		ys[i] = y
	}
	yPrime, ok := curve.Scalar.Random(rand.Reader).(curves.PairingScalar)
	if !ok {
		return nil, errors.New("incorrect type conversion")
	}

	secretKey := &SecretKey{
		x:      x,
		ys:     ys,
		yPrime: yPrime,
	}

	return secretKey, nil
}
