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

package filter

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"gnunet/util"
)

// BloomFilter is a space-efficient probabilistic datastructure to test if
// an element is part of a set of elementsis defined as a string of bits
// always initially empty. An optional mutator can be used to additionally
// "randomize" the computation of the bloomfilter while remaining deterministic.
type BloomFilter struct {
	Bits []byte // filter bits

	// transient attributes
	mInput []byte // mutator input
	mData  []byte // mutator data
}

// NewBloomFilter creates a new empty filter of given size (8*n bits).
func NewBloomFilter(n int) *BloomFilter {
	return &BloomFilter{
		Bits:   make([]byte, n),
		mInput: nil,
		mData:  nil,
	}
}

// SetMutator to define a mutator for randomization. If 'm' is nil,
// the mutator is removed from the filter (use with care!)
func (bf *BloomFilter) SetMutator(m any) {
	// handle mutator input
	switch v := m.(type) {
	case uint32:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)
		bf.mInput = buf.Bytes()
	case []byte:
		bf.mInput = make([]byte, 4)
		util.CopyAlignedBlock(bf.mInput, v)
	case nil:
		bf.mInput = nil
		bf.mData = nil
		return
	}
	// generate mutator bytes
	h := sha512.New()
	h.Write(bf.mInput)
	bf.mData = h.Sum(nil)

	//logger.Printf(logger.DBG, "[filter] Mutator %s -> %s", hex.EncodeToString(bf.mInput), hex.EncodeToString(bf.mData))
}

// Mutator returns the mutator input as a 4-byte array
func (bf *BloomFilter) Mutator() []byte {
	return bf.mInput
}

// Bytes returns the binary representation of a bloom filter
func (bf *BloomFilter) Bytes() []byte {
	var buf []byte
	if bf.mInput != nil {
		buf = append(buf, bf.mInput...)
	}
	buf = append(buf, bf.Bits...)
	return buf
}

// Clone a bloom filter instance
func (bf *BloomFilter) Clone() *BloomFilter {
	return &BloomFilter{
		Bits:   util.Clone(bf.Bits),
		mInput: util.Clone(bf.mInput),
		mData:  util.Clone(bf.mData),
	}
}

// Add entry (binary representation):
// When adding an element to the Bloom filter bf using BF-SET(bf,e), each
// integer n of the mapping M(e) is interpreted as a bit offset n mod L
// within bf and set to 1.
func (bf *BloomFilter) Add(e []byte) {
	for _, idx := range bf.indices(e) {
		bf.Bits[idx/8] |= (1 << (idx % 8))
	}
}

// Contains returns true if the entry is most likely to be included:
// When testing if an element may be in the Bloom filter bf using
// BF-TEST(bf,e), each bit offset n mod L within bf MUST have been set to 1.
// Otherwise, the element is not considered to be in the Bloom filter.
func (bf *BloomFilter) Contains(e []byte) bool {
	for _, idx := range bf.indices(e) {
		if bf.Bits[idx/8]&(1<<(idx%8)) == 0 {
			return false
		}
	}
	return true
}

// indices returns the list of bit indices for antry e:
// The element e is hashed using SHA-512. If a mutator is present, the
// hash values are XOR-ed. The resulting value is interpreted as a list
// of 16 32-bit integers in network byte order.
func (bf *BloomFilter) indices(e []byte) []uint32 {
	// hash the entry
	h := sha512.Sum512(e)
	// apply mutator if available
	if bf.mData != nil {
		for i := range h {
			h[i] ^= bf.mData[i]
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
	/*
		// TEST:
		count := func(d []byte) int {
			num := 0
			for _, v := range d {
				var i byte
				for i = 1; i < 128; i <<= 1 {
					if v&i == i {
						num++
					}
				}
			}
			return num
		}
		logger.Printf(logger.DBG, "[filter] bits = %d:%s (%d set)", len(bf.Bits), hex.EncodeToString(bf.Bits), count(bf.Bits))
		logger.Printf(logger.DBG, "[filter] elem = %s", hex.EncodeToString(e))
		if bf.mData != nil {
			logger.Printf(logger.DBG, "[filter] sha512(elem)^mutator = %s", hex.EncodeToString(h[:]))
		} else {
			logger.Printf(logger.DBG, "[filter] sha512(elem) = %s", hex.EncodeToString(h[:]))
		}
		logger.Printf(logger.DBG, "[filter] indices = %v", idx)
		s := 128
		if bf.mInput != nil {
			s = 124
		}
		bft := NewBloomFilter(s)
		if bf.mInput != nil {
			bft.SetMutator(bf.mInput)
		}
		for _, i := range idx {
			bft.Bits[i/8] |= (1 << (i % 7))
		}
		logger.Printf(logger.DBG, "[filter] bits' = %d:%s (%d set)", len(bft.Bits), hex.EncodeToString(bft.Bits), count(bft.Bits))
	*/
	return idx
}
