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
	"gnunet/crypto"
	"gnunet/enums"
)

// BlockHandler interface defines methods specific to block types.
type BlockHandler interface {

	// Parse a block instance from binary data
	ParseBlock(buf []byte) (Block, error)

	// ValidateBlockQuery is used to evaluate the request for a block as part
	// of DHT-P2P-GET processing. Here, the block payload is unknown, but if
	// possible the XQuery and Key SHOULD be verified.
	ValidateBlockQuery(key *crypto.HashCode, xquery []byte) bool

	// ValidateBlockKey returns true if the block key is the same as the
	// query key used to access the block.
	ValidateBlockKey(b Block, key *crypto.HashCode) bool

	// DeriveBlockKey is used to synthesize the block key from the block
	// payload as part of PutMessage and ResultMessage processing. The special
	// return value of 'nil' implies that this block type does not permit
	// deriving the key from the block. A Key may be returned for a block that
	// is ill-formed.
	DeriveBlockKey(b Block) *crypto.HashCode

	// ValidateBlockStoreRequest is used to evaluate a block payload as part of
	// PutMessage and ResultMessage processing.
	ValidateBlockStoreRequest(b Block) bool

	// SetupResultFilter is used to setup an empty result filter. The arguments
	// are the set of results that must be filtered at the initiator, and a
	// MUTATOR value which MAY be used to deterministically re-randomize
	// probabilistic data structures.
	SetupResultFilter(filterSize int, mutator uint32) ResultFilter

	// ParseResultFilter from binary data
	ParseResultFilter(data []byte) ResultFilter

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
	FilterResult(b Block, key *crypto.HashCode, rf ResultFilter, xQuery []byte) int
}

// BlockHandlers is a map of block query validation implementations
// for supported block types.
var BlockHandlers map[enums.BlockType]BlockHandler

// initializer function
func init() {
	// create map instance
	BlockHandlers = make(map[enums.BlockType]BlockHandler)

	// add validation functions
	BlockHandlers[enums.BLOCK_TYPE_DHT_URL_HELLO] = new(HelloBlockHandler)
	BlockHandlers[enums.BLOCK_TYPE_TEST] = new(TestBlockHandler)
}
