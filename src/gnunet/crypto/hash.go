// This file is part of gnunet-go, a GNUnet-implementation in Golang.
// Copyright (C) 2019, 2020 Bernd Fix  >Y<
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

package crypto

import (
	"bytes"
	"crypto/sha512"

	"gnunet/util"
)

// HashCode is the result of a 512-bit hash function (SHA-512)
type HashCode struct {
	Bits []byte `size:"64"`
}

// Equals tests if two hash results are equal.
func (hc *HashCode) Equals(n *HashCode) bool {
	return bytes.Equal(hc.Bits, n.Bits)
}

// NewHashCode creates a new (initalized) hash value
func NewHashCode(buf []byte) *HashCode {
	hc := &HashCode{
		Bits: make([]byte, 64),
	}
	if buf != nil {
		util.CopyAlignedBlock(hc.Bits, buf)
	}
	return hc
}

// Hash returns the SHA-512 hash value of a given blob
func Hash(data []byte) *HashCode {
	val := sha512.Sum512(data)
	return &HashCode{
		Bits: util.Clone(val[:]),
	}
}
