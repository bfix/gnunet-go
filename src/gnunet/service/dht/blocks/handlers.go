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

const (
	RF_MORE       = iota // Valid result, and there may be more.
	RF_LAST              // Last possible valid result.
	RF_DUPLICATE         // Valid result, but duplicate (was filtered by the result filter).
	RF_IRRELEVANT        // Block does not satisfy the constraints imposed by the XQuery.
)

//----------------------------------------------------------------------

// BlockHandler interface defines methods specific to block types.
type BlockHandler interface {

	// ValidateBlockQuery is used to evaluate the request for a block as part of
	// DHT-P2P-GET processing. Here, the block payload is unknown, but if possible
	// the XQuery and Key SHOULD be verified.
	ValidateBlockQuery(key *crypto.HashCode, xquery []byte) bool

	// SetupResultFilter is used to setup an empty result filter. The arguments
	// are the set of results that must be filtered at the initiator, and a
	// MUTATOR value which MAY be used to deterministically re-randomize
	// probabilistic data structures.
	SetupResultFilter(filterSize int, mutator uint32) []byte

	// FilterResult is used to filter results against specific queries. This
	// function does not check the validity of the block itself or that it
	// matches the given key, as this must have been checked earlier. Thus,
	// locally stored blocks from previously observed ResultMessages and
	// PutMessages use this function to perform filtering based on the request
	// parameters of a particular GET operation. Possible values for the
	// FilterEvaluationResult are defined above. If the main evaluation result
	// is RF_MORE, the function also returns and updated result filter where
	// the block is added to the set of filtered replies. An implementation is
	// not expected to actually differenciate between the RF_DUPLICATE and
	// RF_IRRELEVANT return values: in both cases the block is ignored for
	// this query.
	FilterResult(b Block, key *crypto.HashCode, rf []byte, xQuery []byte) ([]byte, []byte)

	// ValidateBlockStoreRequest is used to evaluate a block payload as part of
	// PutMessage and ResultMessage processing.
	ValidateBlockStoreRequest(b Block) bool
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
}
