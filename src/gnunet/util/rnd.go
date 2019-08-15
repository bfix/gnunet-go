package util

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
)

func RndArray(b []byte) {
	rand.Read(b)
}

func NewRndArray(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}

func RndUInt64() uint64 {
	b := make([]byte, 8)
	RndArray(b)
	var v uint64
	c := bytes.NewBuffer(b)
	binary.Read(c, binary.BigEndian, &v)
	return v
}

func RndInt64() int64 {
	return int64(RndUInt64())
}

func RndUInt32() uint32 {
	return uint32(RndUInt64())
}

func RndInt32() int32 {
	return int32(RndUInt64())
}

func RndUInt16() uint16 {
	return uint16(RndUInt64())
}

func RndInt16() int16 {
	return int16(RndUInt64())
}
