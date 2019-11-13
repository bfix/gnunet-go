package util

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

// RndArray fills a buffer with random content
func RndArray(b []byte) {
	rand.Read(b)
}

// NewRndArray creates a new buffer of given size; filled with random content.
func NewRndArray(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

// RndUInt64 returns a new 64-bit unsigned random integer.
func RndUInt64() uint64 {
	b := make([]byte, 8)
	RndArray(b)
	var v uint64
	c := bytes.NewBuffer(b)
	binary.Read(c, binary.BigEndian, &v)
	return v
}

// RndInt64 returns a new 64-bit signed random integer.
func RndInt64() int64 {
	return int64(RndUInt64())
}

// RndUInt32 returns a new 32-bit unsigned random integer.
func RndUInt32() uint32 {
	return uint32(RndUInt64())
}

// RndInt32 returns a new 32-bit signed random integer.
func RndInt32() int32 {
	return int32(RndUInt64())
}

// RndUInt16 returns a new 16-bit unsigned random integer.
func RndUInt16() uint16 {
	return uint16(RndUInt64())
}

// RndInt16 returns a new 16-bit signed random integer.
func RndInt16() int16 {
	return int16(RndUInt64())
}
