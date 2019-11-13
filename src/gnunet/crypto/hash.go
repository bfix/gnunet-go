package crypto

import (
	"crypto/sha512"

	"gnunet/util"
)

// HashCode is the result of a 512-bit hash function (SHA-512)
type HashCode struct {
	Bits []byte `size:"64"`
}

// NewHashCode creates a new, uninitalized hash value
func NewHashCode() *HashCode {
	return &HashCode{
		Bits: make([]byte, 64),
	}
}

// Hash returns the SHA-512 hash value of a given blob
func Hash(data []byte) *HashCode {
	val := sha512.Sum512(data)
	return &HashCode{
		Bits: util.Clone(val[:]),
	}
}
