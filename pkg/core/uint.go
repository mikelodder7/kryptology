package core

import "fmt"

const MaxUintBytes = 10

// Uint implements zig-zag encoding for efficiently
// representing integers in binary.
type Uint struct {
	uint64
}

func (u Uint) Uint() uint {
	return uint(u.uint64)
}

func (u *Uint) SetUint(x uint) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Uint64() uint64 {
	return u.uint64
}

func (u *Uint) SetUint64(x uint64) *Uint {
	u.uint64 = x
	return u
}

func (u *Uint) Uint32() uint32 {
	return uint32(u.uint64)
}

func (u *Uint) SetUint32(x uint32) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Uint16() uint32 {
	return uint32(u.uint64)
}

func (u *Uint) SetUint16(x uint16) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Uint8() byte {
	return byte(u.uint64)
}

func (u *Uint) SetUint8(x byte) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Int() int {
	return int(u.uint64)
}

func (u *Uint) SetInt(x int) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Int64() int64 {
	return int64(u.uint64)
}

func (u *Uint) SetInt64(x int64) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Int32() int32 {
	return int32(u.uint64)
}

func (u *Uint) SetInt32(x int32) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Int16() int16 {
	return int16(u.uint64)
}

func (u *Uint) SetInt16(x int16) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u *Uint) Int8() int8 {
	return int8(u.uint64)
}

func (u *Uint) SetInt8(x int8) *Uint {
	u.uint64 = uint64(x)
	return u
}

func (u Uint) Bytes() []byte {
	// zig-zag encoding
	var buf [MaxUintBytes]byte
	i := 0
	x := u.uint64
	for x >= 0x80 {
		buf[i] = byte(x) | 0x80
		x >>= 7
		i++
	}
	buf[i] = byte(x)
	i++
	return buf[:i]
}

// Peek returns the number of bytes that would be read
// or an error if an Uint cannot be read.
func (Uint) Peek(input []byte) (int, error) {
	i := 0
	for ; i < MaxUintBytes; i++ {
		if i > len(input) {
			return 0, fmt.Errorf("invalid byte sequence")
		}
		if input[i] < 0x80 {
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("invalid byte sequence")
}

func (u Uint) MarshalBinary() ([]byte, error) {
	return u.Bytes(), nil
}

func (u *Uint) UnmarshalBinary(input []byte) error {
	x := uint64(0)
	s := 0
	i := 0
	for ; i < MaxUintBytes; i++ {
		if i > len(input) {
			return fmt.Errorf("invalid byte sequence")
		}
		b := input[i]
		if b < 0x80 {
			u.uint64 = x | uint64(b)<<s
			return nil
		}
		x |= uint64(b&0x7F) << s
		s += 7
	}
	return fmt.Errorf("invalid variable-length integer")
}
