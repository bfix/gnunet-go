package util

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	tests = []struct {
		bin []byte
		str string
	}{
		{[]byte{
			0xD4,
		}, "TG"},
		{[]byte{
			0x78, 0xD3,
		}, "F39G"},
		{[]byte{
			0x43, 0xA4, 0x59, 0x57,
		}, "8EJ5JNR"},
		{[]byte{
			0x59, 0x40, 0xB3, 0x2D, 0xB8, 0x86, 0x61, 0xC2,
		}, "B50B6BDRGSGW4"},
		{[]byte{
			0xF9, 0x7F, 0x85, 0x6D, 0x8D, 0x8D, 0x65, 0x91,
			0x50, 0x3A, 0x2F, 0x36, 0x9F, 0x63, 0x01, 0x45,
		}, "Z5ZRAVCDHNJS2M1T5WV9YRR18M"},
		{[]byte{
			0x7B, 0x46, 0x0D, 0xFD, 0xC9, 0x04, 0xA6, 0x99,
			0x54, 0x94, 0xB0, 0xCE, 0xFE, 0x17, 0x72, 0x31,
			0xC8, 0x90, 0xBA, 0x9F, 0x3C, 0xD1, 0x42, 0xA1,
		}, "FD30VZE90JK9JN4MP37FW5VJ67491EMZ7K8M588"},
		{[]byte{
			0xC0, 0x78, 0x05, 0x04, 0xB8, 0xE2, 0x4A, 0xA5,
			0x61, 0x82, 0xCE, 0xCC, 0xE3, 0xCA, 0x53, 0x01,
			0x67, 0x5F, 0xA3, 0x05, 0xA9, 0x27, 0xC5, 0xE2,
			0x6B, 0xB5, 0xB5, 0x86, 0xAB, 0x84, 0x32, 0x6C,
		}, "R1W0A15RW95AARC2SV6E7JJK05KNZ8R5N4KWBRKBPPTRDAW469P0"},
	}
)

func TestBase32Preset(t *testing.T) {
	for _, x := range tests {
		s := EncodeBinaryToString(x.bin)
		if testing.Verbose() {
			fmt.Printf("[%s] ==> %s\n", hex.EncodeToString(x.bin), s)
		}
		if s != x.str {
			t.Fatalf("Encoding mismatch: '%s' != '%s' for %s\n", s, x.str, hex.EncodeToString(x.bin))
		}
		e, err := DecodeStringToBinary(x.str, len(x.bin))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(x.bin, e) != 0 {
			t.Fatalf("Decoding mismatch: '%s' != '%s' for '%s'\n", hex.EncodeToString(e), hex.EncodeToString(x.bin), x.str)
		}
	}
}

func TestBase32Random(t *testing.T) {
	buf := make([]byte, 32)
	for i := 0; i < 100; i++ {
		n, err := rand.Read(buf)
		if err != nil || n != 32 {
			t.Fatal(err)
		}
		s := EncodeBinaryToString(buf)
		r, err := DecodeStringToBinary(s, len(buf))
		if err != nil {
			t.Fatal(err)
		}
		if len(buf) != len(r) {
			x := make([]byte, len(buf))
			n := len(buf) - len(r)
			copy(x[n:], r)
			r = x
		}
		if !bytes.Equal(buf, r) {
			t.Fatal("Encode/Decode mismatch")
		}
	}
}
