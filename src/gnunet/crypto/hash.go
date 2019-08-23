package crypto

import (
	"crypto/sha512"

	"gnunet/util"
)

type HashCode struct {
	Bits []byte `size:"64"`
}

func NewHashCode() *HashCode {
	return &HashCode{
		Bits: make([]byte, 64),
	}
}

func Hash(data []byte) *HashCode {
	val := sha512.Sum512(data)
	return &HashCode{
		Bits: util.Clone(val[:]),
	}
}
