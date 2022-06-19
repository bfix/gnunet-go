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
	"crypto/sha512"
	"encoding/binary"
)

// BloomFilter is a space-efficient probabilistic datastructure to test if
// an element is part of a set of elementsis defined as a string of bits
// always initially empty. An optional mutator can be used to additionally
// "randomize" the computation of the bloomfilter while remaining deterministic.
type BloomFilter struct {
	Bits    []byte // filter bits
	mutator []byte // mutator data (transient)
}

// NewBloomFilter creates a new empty filter of given size (8*n bits).
func NewBloomFilter(n int) *BloomFilter {
	return &BloomFilter{
		Bits:    make([]byte, n),
		mutator: nil,
	}
}

// NewBloomFilterFromBytes creates a new BloomFilter from a binary
// representation: 'data' is the concatenaion 'mutator|bloomfilter' where
// 'mSize' is the size of the mutator in bytes. If 'msize' is 0, no
// mutator is used.
func NewBloomFilterFromBytes(data []byte, mSize int) *BloomFilter {
	bf := &BloomFilter{
		Bits:    Clone(data[mSize:]),
		mutator: nil,
	}
	if mSize > 0 {
		bf.SetMutator(data[:mSize])
	}
	return bf
}

// SetMutator to define a mutator for randomization.
func (bf *BloomFilter) SetMutator(m any) {
	var data []byte
	switch v := m.(type) {
	case uint32:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)
		data = buf.Bytes()
	case []byte:
		data = Clone(v)
	}
	h := sha512.Sum512(data)
	bf.mutator = make([]byte, 64)
	copy(bf.mutator, h[:])
}

// Add entry (binary representation):
// When adding an element to the Bloom filter bf using BF-SET(bf,e), each
// integer n of the mapping M(e) is interpreted as a bit offset n mod L
// within bf and set to 1.
func (bf *BloomFilter) Add(e []byte) {
	for _, idx := range bf.indices(e) {
		bf.Bits[idx/8] |= (1 << (idx % 7))
	}
}

// Contains returns true if the entry is most likely to be included:
// When testing if an element may be in the Bloom filter bf using
// BF-TEST(bf,e), each bit offset n mod L within bf MUST have been set to 1.
// Otherwise, the element is not considered to be in the Bloom filter.
func (bf *BloomFilter) Contains(e []byte) bool {
	for _, idx := range bf.indices(e) {
		if bf.Bits[idx/8]&(1<<(idx%7)) == 0 {
			return false
		}
	}
	return true
}

// indices returns the list of bit indices for antry e:
// The element e is prepended with a salt (pütional) and hashed using SHA-512.
// The resulting byte string is interpreted as a list of 16 32-bit integers
// in network byte order.
func (bf *BloomFilter) indices(e []byte) []uint32 {
	// hash the entry
	h := sha512.Sum512(e)
	// apply mutator if available
	if bf.mutator != nil {
		for i := range h {
			h[i] ^= bf.mutator[i]
		}
	}
	// compute the indices for the entry
	size := uint32(8 * len(bf.Bits))
	idx := make([]uint32, 16)
	buf := bytes.NewReader(h[:])
	for i := range idx {
		binary.Read(buf, binary.BigEndian, &idx[i])
		idx[i] %= size
	}
	return idx
}
