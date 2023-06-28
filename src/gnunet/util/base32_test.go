// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019-2022 Bernd Fix  >Y<
//
// gnunet-go is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// gnunet-go is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL3.0-or-later

package util

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
			t.Logf("[%s] ==> %s\n", hex.EncodeToString(x.bin), s)
		}
		if s != x.str {
			t.Fatalf("Encoding mismatch: '%s' != '%s' for %s\n", s, x.str, hex.EncodeToString(x.bin))
		}
		e, err := DecodeStringToBinary(x.str, len(x.bin))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x.bin, e) {
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

func TestBase32RFC(t *testing.T) {
	var (
		i1 = []byte{0x59, 0x40, 0xB3, 0x2D, 0xB8, 0x86, 0x61, 0xC2}
		o1 = "B50B6BDRGSGW4"
		i2 = []byte("Hello World")
		o2 = "91JPRV3F41BPYWKCCG"
		o3 = "91JPRU3F4IBPYWKCCG"
		o4 = "91JPR+3F4!BPYWKCCG"
	)
	if EncodeBinaryToString(i1) != o1 {
		t.Fatal("RFC-1")
	}
	if i, err := DecodeStringToBinary(o1, 8); err != nil || !bytes.Equal(i, i1) {
		t.Fatal("RFC-2")
	}
	if EncodeBinaryToString(i2) != o2 {
		t.Fatal("RFC-3")
	}
	if i, err := DecodeStringToBinary(o2, 11); err != nil || !bytes.Equal(i, i2) {
		t.Fatal("RFC-3")
	}
	if i, err := DecodeStringToBinary(o3, 11); err != nil || !bytes.Equal(i, i2) {
		t.Fatal("RFC-4")
	}
	if _, err := DecodeStringToBinary(o4, 11); err == nil {
		t.Fatal("RFC-5")
	}
}
