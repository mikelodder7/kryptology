package core

import (
	"bytes"

	"github.com/pkg/errors"
)

type ByteSerializer struct {
	buffer  *bytes.Buffer
	lastLen *Uint
}

func NewByteSerializer(initialCapacity uint) *ByteSerializer {
	buffer := bytes.NewBuffer(make([]byte, 0, initialCapacity))
	lastLen := new(Uint)
	return &ByteSerializer{buffer, lastLen}
}

func (b *ByteSerializer) WriteBytes(input []byte) (int, error) {
	b.lastLen.SetInt(len(input))
	c1, err := b.buffer.Write(b.lastLen.Bytes())
	if err != nil {
		return 0, errors.WithStack(err)
	}
	c2, err := b.buffer.Write(input)
	if err != nil {
		return c1, errors.WithStack(err)
	}
	return c1 + c2, nil
}

func (b *ByteSerializer) WriteByteArray(input [][]byte) (int, error) {
	b.lastLen.SetInt(len(input))
	count, err := b.buffer.Write(b.lastLen.Bytes())
	if err != nil {
		return 0, errors.WithStack(err)
	}
	for _, i := range input {
		c1, err := b.WriteBytes(i)
		if err != nil {
			return 0, errors.WithStack(err)
		}
		count += c1
	}
	return count, nil
}

func (b *ByteSerializer) WriteString(input string) (int, error) {
	b.lastLen.SetInt(len(input))
	c1, err := b.buffer.Write(b.lastLen.Bytes())
	if err != nil {
		return 0, errors.WithStack(err)
	}
	c2, err := b.buffer.Write([]byte(input))
	if err != nil {
		return c1, errors.WithStack(err)
	}
	return c1 + c2, nil
}

func (b *ByteSerializer) WriteBool(input bool) (int, error) {
	var err error
	if input {
		err = b.buffer.WriteByte(1)
	} else {
		err = b.buffer.WriteByte(0)
	}
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return 1, nil
}

func (b *ByteSerializer) Bytes() []byte {
	return b.buffer.Bytes()
}

type ByteDeserializer struct {
	lastLen *Uint
	buffer  []byte
	offset  int
}

func NewByteDeserializer(input []byte) *ByteDeserializer {
	return &ByteDeserializer{
		lastLen: new(Uint),
		buffer:  input,
		offset:  0,
	}
}

func (b *ByteDeserializer) ReadBytes() ([]byte, error) {
	var count int
	var err error
	end := b.offset + MaxUintBytes
	if end > len(b.buffer) {
		return nil, errors.New("not enough bytes")
	}
	if count, err = b.lastLen.Peek(b.buffer[b.offset:end]); err != nil {
		return nil, errors.WithStack(err)
	}
	if err = b.lastLen.UnmarshalBinary(b.buffer[b.offset:end]); err != nil {
		return nil, errors.WithStack(err)
	}
	b.offset += count
	end = b.offset + b.lastLen.Int()
	if end > len(b.buffer) {
		return nil, errors.New("invalid byte sequence")
	}
	item := b.buffer[b.offset:end]
	b.offset = end
	return item, nil
}

func (b *ByteDeserializer) ReadByteArray() ([][]byte, error) {
	var count, length int
	var err error
	end := b.offset + MaxUintBytes
	if count, err = b.lastLen.Peek(b.buffer[b.offset:end]); err != nil {
		return nil, errors.WithStack(err)
	}
	if err = b.lastLen.UnmarshalBinary(b.buffer[b.offset:end]); err != nil {
		return nil, errors.WithStack(err)
	}
	length = b.lastLen.Int()

	output := make([][]byte, length)

	b.offset += count
	for i := 0; i < length; i++ {
		item, err := b.ReadBytes()
		if err != nil {
			return nil, errors.WithStack(err)
		}
		output[i] = item
	}
	return output, nil
}

func (b *ByteDeserializer) ReadString() (string, error) {
	value, err := b.ReadBytes()
	if err != nil {
		return "", errors.WithStack(err)
	}
	return string(value), nil
}

func (b *ByteDeserializer) ReadBool() (bool, error) {
	var value bool
	switch b.buffer[b.offset] {
	case 1:
		value = true
	case 0:
		value = false
	default:
		return false, errors.New("invalid bool value")
	}
	b.offset++
	return value, nil
}
