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

package blocks

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"gnunet/util"

	"github.com/bfix/gospel/logger"
)

//======================================================================
// Peer filter
//======================================================================

// PeerFilter is a bloom filter without mutator
type PeerFilter struct {
	BF *BloomFilter
}

// NewPeerFilter creates an empty peer filter instance.
func NewPeerFilter() *PeerFilter {
	return &PeerFilter{
		BF: NewBloomFilter(128),
	}
}

// Add peer id to the filter
func (pf *PeerFilter) Add(p *util.PeerID) {
	pf.BF.Add(p.Data)
}

// Contains returns true if the peer id is filtered (in the filter)
func (pf *PeerFilter) Contains(p *util.PeerID) bool {
	return pf.BF.Contains(p.Data)
}

// Cloone peer filter instance
func (pf *PeerFilter) Clone() *PeerFilter {
	return &PeerFilter{
		BF: pf.BF.Clone(),
	}
}

//======================================================================
// Result filter
//======================================================================

// ResultFilter return values
//nolint:stylecheck // allow non-camel-case in constants
const (
	RF_MORE       = iota // Valid result, and there may be more.
	RF_LAST              // Last possible valid result.
	RF_DUPLICATE         // Valid result, but duplicate (was filtered by the result filter).
	RF_IRRELEVANT        // Block does not satisfy the constraints imposed by the XQuery.
)

// Compare return values
//nolint:stylecheck // allow non-camel-case in constants
const (
	CMP_SAME   = iota // the two result filter are the same
	CMP_MERGE         // the two result filter can be merged
	CMP_DIFFER        // the two result filter are different
	CMP_1             // used as state by derived/complex compare functions
	CMP_2
	CMP_3
)

//----------------------------------------------------------------------

// ResultFilter is used to indicate to other peers which results are not of
// interest when processing a GetMessage. Any peer which is processing
// GetMessages and has a result which matches the query key MUST check the
// result filter and only send a reply message if the result does not test
// positive under the result filter. Before forwarding the GetMessage, the
// result filter MUST be updated to filter out all results already returned
// by the local peer.
type ResultFilter interface {

	// Add entry to filter
	Add(Block)

	// Contains returns true if entry is filtered
	Contains(Block) bool

	// Bytes returns the binary representation of a result filter
	Bytes() []byte

	// Compare two result filters
	Compare(ResultFilter) int

	// Merge two result filters
	Merge(ResultFilter) bool
}

//----------------------------------------------------------------------
// Dummy result filter
// [Additional filters (per block type) are defined in corresponding files]
//----------------------------------------------------------------------

// PassResultFilter is a dummy result filter with no state.
type PassResultFilter struct{}

// Add a block to the result filter.
func (rf *PassResultFilter) Add(Block) {
}

// Contains returns true if entry (binary representation) is filtered
func (rf *PassResultFilter) Contains(Block) bool {
	return false
}

// Bytes returns the binary representation of a result filter
func (rf *PassResultFilter) Bytes() (buf []byte) {
	return
}

// Merge two result filters
func (rf *PassResultFilter) Merge(ResultFilter) bool {
	return true
}

// Compare two result filters
func (rf *PassResultFilter) Compare(t ResultFilter) int {
	if _, ok := t.(*PassResultFilter); ok {
		return CMP_SAME
	}
	return CMP_DIFFER
}

//======================================================================
// Generic bllom filter with mutator
//======================================================================

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
		if err := binary.Write(buf, binary.BigEndian, v); err != nil {
			logger.Printf(logger.ERROR, "[BloomFilter.SetMutator] failed: %s", err.Error())
		}
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
	if _, err := h.Write(bf.mInput); err != nil {
		logger.Printf(logger.ERROR, "[BloomFilter.SetMutator] failed: %s", err.Error())
	}
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

// Compare two bloom filters
func (bf *BloomFilter) Compare(a *BloomFilter) int {
	if len(bf.Bits) != len(a.Bits) || !bytes.Equal(bf.mInput, a.mInput) {
		return CMP_DIFFER
	}
	if bytes.Equal(bf.Bits, a.Bits) {
		return CMP_SAME
	}
	return CMP_MERGE
}

// Merge two bloom filters
func (bf *BloomFilter) Merge(a *BloomFilter) bool {
	if len(bf.Bits) != len(a.Bits) || !bytes.Equal(bf.mInput, a.mInput) {
		return false
	}
	for i := range bf.Bits {
		bf.Bits[i] |= a.Bits[i]
	}
	return true
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
		if err := binary.Read(buf, binary.BigEndian, &idx[i]); err != nil {
			logger.Printf(logger.ERROR, "[BloomFilter.indices] failed: %s", err.Error())
		}
		idx[i] %= size
	}
	return idx
}
