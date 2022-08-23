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
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
	"gnunet/util"
)

//----------------------------------------------------------------------
// TEST block
//----------------------------------------------------------------------

// TestBlock (BLOCK_TYPE_TEST) is a block for testing the DHT with non-HELLO
// blocks. Applications using the DHT are encouraged to define custom blocks
// with appropriate internal logic. TestBlocks are just a pile of bits...
type TestBlock struct {
	Data []byte `size:"*"`
}

// Return the block type
func (t *TestBlock) Type() enums.BlockType {
	return enums.BLOCK_TYPE_TEST
}

// Bytes returns the raw block data
func (t *TestBlock) Bytes() []byte {
	return util.Clone(t.Data)
}

// Expire returns the block expiration
func (t *TestBlock) Expire() util.AbsoluteTime {
	return util.AbsoluteTimeNever()
}

// String returns the human-readable representation of a block
func (t *TestBlock) String() string {
	return fmt.Sprintf("TestBlock{%d bytes}", len(t.Data))
}

// Verify the integrity of a block (optional). Override in custom query
// types to implement block-specific integrity checks (see GNSBlock for
// example). This verification is usually weaker than the verification
// method from a Query (see GNSBlock.Verify for explanation).
func (t *TestBlock) Verify() (bool, error) {
	// no internal verification defined. All good.
	return true, nil
}

//----------------------------------------------------------------------
// TEST block handler
//----------------------------------------------------------------------

// TestBlockHandler methods related to HELLO blocks
type TestBlockHandler struct{}

// Parse a block instance from binary data
func (bh *TestBlockHandler) ParseBlock(buf []byte) (Block, error) {
	return &TestBlock{
		Data: util.Clone(buf),
	}, nil
}

// ValidateHelloBlockQuery validates query parameters for a
// DHT-GET request for HELLO blocks.
func (bh *TestBlockHandler) ValidateBlockQuery(key *crypto.HashCode, xquery []byte) bool {
	// no internal logic
	return true
}

// ValidateBlockKey returns true if the block key is the same as the
// query key used to access the block.
func (bh *TestBlockHandler) ValidateBlockKey(b Block, key *crypto.HashCode) bool {
	// no internal logic
	return true
}

// DeriveBlockKey is used to synthesize the block key from the block
// payload as part of PutMessage and ResultMessage processing. The special
// return value of 'nil' implies that this block type does not permit
// deriving the key from the block. A Key may be returned for a block that
// is ill-formed.
func (bh *TestBlockHandler) DeriveBlockKey(b Block) *crypto.HashCode {
	return nil
}

// ValidateBlockStoreRequest is used to evaluate a block payload as part of
// PutMessage and ResultMessage processing.
// To validate a block store request is to verify the EdDSA SIGNATURE over
// the hashed ADDRESSES against the public key from the peer ID field. If the
// signature is valid true is returned.
func (bh *TestBlockHandler) ValidateBlockStoreRequest(b Block) bool {
	// no internal logic
	return true
}

// SetupResultFilter is used to setup an empty result filter. The arguments
// are the set of results that must be filtered at the initiator, and a
// MUTATOR value which MAY be used to deterministically re-randomize
// probabilistic data structures.
func (bh *TestBlockHandler) SetupResultFilter(filterSize int, mutator uint32) ResultFilter {
	return NewGenericResultFilter(filterSize, mutator)
}

// ParseResultFilter from binary data
func (bh *TestBlockHandler) ParseResultFilter(data []byte) ResultFilter {
	return NewGenericResultFilterFromBytes(data)
}

// FilterResult is used to filter results against specific queries. This
// function does not check the validity of the block itself or that it
// matches the given key, as this must have been checked earlier. Thus,
// locally stored blocks from previously observed ResultMessages and
// PutMessages use this function to perform filtering based on the request
// parameters of a particular GET operation. Possible values for the
// FilterEvaluationResult are defined above. If the main evaluation result
// is RF_MORE, the function also returns and updated result filter where
// the block is added to the set of filtered replies. An implementation is
// not expected to actually differentiate between the RF_DUPLICATE and
// RF_IRRELEVANT return values: in both cases the block is ignored for
// this query.
func (bh *TestBlockHandler) FilterResult(b Block, key *crypto.HashCode, rf ResultFilter, xQuery []byte) int {
	if rf.Contains(b) {
		return RF_DUPLICATE
	}
	rf.Add(b)
	return RF_LAST
}
