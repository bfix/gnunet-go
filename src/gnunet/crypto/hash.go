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

package crypto

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"

	"gnunet/util"
)

// HashCode is the result of a 512-bit hash function (SHA-512)
type HashCode struct {
	Data []byte `size:"(Size)"`
}

// Equal tests if two hash results are equal.
func (hc *HashCode) Equal(n *HashCode) bool {
	return bytes.Equal(hc.Data, n.Data)
}

// Size of binary data
func (hc *HashCode) Size() uint {
	return 64
}

// Clone the hash code
func (hc *HashCode) Clone() *HashCode {
	return &HashCode{
		Data: util.Clone(hc.Data),
	}
}

// String returns a hex-representation of the hash code
func (hc *HashCode) String() string {
	return hex.EncodeToString(hc.Data)
}

// Short returns a short key representation
func (hc *HashCode) Short() string {
	return util.Shorten(hc.String(), 20)
}

// NewHashCode creates a new (initialized) hash value
func NewHashCode(data []byte) *HashCode {
	hc := new(HashCode)
	size := hc.Size()
	v := make([]byte, size)
	if len(data) > 0 {
		if uint(len(data)) < size {
			util.CopyAlignedBlock(v, data)
		} else {
			copy(v, data[:size])
		}
	}
	hc.Data = v
	return hc
}

// Hash returns the SHA-512 hash value of a given blob
func Hash(data []byte) *HashCode {
	val := sha512.Sum512(data)
	return &HashCode{
		Data: util.Clone(val[:]),
	}
}
