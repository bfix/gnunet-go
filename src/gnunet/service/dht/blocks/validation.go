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

	"github.com/bfix/gospel/crypto/ed25519"
)

//----------------------------------------------------------------------

// ValidateBlockQuery is used to evaluate the request for a block as part of
// DHT-P2P-GET processing. Here, the block payload is unknown, but if possible
// the XQuery and Key SHOULD be verified.
type ValidateBlockQuery func(key *crypto.HashCode, xquery []byte) bool

// BlockQueryValidation is a map of block query validation implementations
// for supported block types.
var BlockQueryValidation map[enums.BlockType]ValidateBlockQuery

// initializer function
func init() {
	// create map instance
	BlockQueryValidation = make(map[enums.BlockType]ValidateBlockQuery)

	// add validation functions
	BlockQueryValidation[enums.BLOCK_TYPE_DHT_URL_HELLO] = ValidateHelloBlockQuery
}

//----------------------------------------------------------------------

// DeriveBlockKey is used to synthesize the block key from the block payload as
// part of PutMessage and ResultMessage processing. Returns nil if this block
// type does not permit deriving the key from the block. A Key may be returned
// for a block that is ill-formed.
func DeriveBlockKey(b Block) *ed25519.PublicKey {
	return nil
}

// ValidateBlockStoreRequest is used to evaluate a block payload as part of
// PutMessage and ResultMessage processing.
func ValidateBlockStoreRequest(b Block) bool {
	return false
}

// SetupResultFilter is used to setup an empty result filter. The arguments
// are the set of results that must be filtered at the initiator, and a
// MUTATOR value which MAY be used to deterministically re-randomize
// probabilistic data structures.
func SetupResultFilter(filterSize int, mutator uint32) []byte {
	return nil
}

func FilterResult(b Block, key *crypto.HashCode, rf []byte, xQuery []byte) ([]byte, []byte) {
	return nil, nil
}
