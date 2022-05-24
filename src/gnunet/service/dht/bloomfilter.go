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

package dht

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
)

//======================================================================
// Generic BloomFilter
//======================================================================

// BloomFilter parameter
var (
	bfNumBits = 128
	bfHash    = sha512.New
)

// BloomFilter is a space-efficient probabilistic datastructure to test if
// an element is part of a set of elementsis defined as a string of bits
// always initially empty.
type BloomFilter struct {
	data []byte // filter bits
	salt []byte // salt for hashing
}

// NewBloomFilter cretes a new filter using the specified salt. An unused
// salt is set to nil.
func NewBloomFilter(salt []byte) *BloomFilter {
	return &BloomFilter{
		data: make([]byte, (bfNumBits+7)/8),
		salt: salt,
	}
}

// Add entry (binary representation):
// When adding an element to the Bloom filter bf using BF-SET(bf,e), each
// integer n of the mapping M(e) is interpreted as a bit offset n mod L
// within bf and set to 1.
func (bf *BloomFilter) Add(e []byte) {
	for _, idx := range bf.indices(e) {
		bf.data[idx/8] |= (1 << (idx % 7))
	}
}

// Contains returns true if the entry is most likely to be included:
// When testing if an element may be in the Bloom filter bf using
// BF-TEST(bf,e), each bit offset n mod L within bf MUST have been set to 1.
// Otherwise, the element is not considered to be in the Bloom filter.
func (bf *BloomFilter) Contains(e []byte) bool {
	for _, idx := range bf.indices(e) {
		if bf.data[idx/8]&(1<<(idx%7)) == 0 {
			return false
		}
	}
	return true
}

// indices returns the list of bit indices for antry e:
// The element e is prepended with a salt (pütional) and hashed using SHA-512.
// The resulting byte string is interpreted as a list of 16 32-bit integers
// in network byte order.
func (bf *BloomFilter) indices(e []byte) []int {
	// hash the entry (with optional salt prepended)
	hsh := bfHash()
	if bf.salt != nil {
		hsh.Write(bf.salt)
	}
	hsh.Write(e)
	h := hsh.Sum(nil)

	// compute the indices for the entry
	idx := make([]int, len(h)/2)
	buf := bytes.NewReader(h)
	for i := range idx {
		binary.Read(buf, binary.BigEndian, &idx[i])
	}
	return idx
}

//======================================================================
// BloomFilter for peer addresses
//======================================================================

// PeerBloomFilter implements specific Add/Contains functions.
type PeerBloomFilter struct {
	BloomFilter
}

// NewPeerBloomFilter creates a new filter for peer addresses.
func NewPeerBloomFilter() *PeerBloomFilter {
	return &PeerBloomFilter{
		BloomFilter: *NewBloomFilter(nil),
	}
}

// Add peer address to the filter.
func (bf *PeerBloomFilter) Add(p *PeerAddress) {
	bf.BloomFilter.Add(p.addr[:])
}

// Contains returns true if the peer address is most likely to be included.
func (bf *PeerBloomFilter) Contains(p *PeerAddress) bool {
	return bf.BloomFilter.Contains(p.addr[:])
}
