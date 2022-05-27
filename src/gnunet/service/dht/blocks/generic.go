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
	"gnunet/util"

	"github.com/bfix/gospel/data"
)

//----------------------------------------------------------------------
// Query/Block interfaces for generic DHT handling
//----------------------------------------------------------------------

// DHT Query interface
type Query interface {

	// Key returns the DHT key for a block
	Key() *crypto.HashCode

	// Type returns the desired block type for results
	Type() uint16

	// Verify the integrity of a retrieved block (optional). Override in
	// custom query types to implement block-specific integrity checks
	// (see GNSQuery for example).
	Verify(blk Block) error

	// Decrypt block content (optional). Override in custom query types to
	// implement block-specific encryption (see GNSQuery for example).
	Decrypt(blk Block) error
}

// DHT Block interface
type Block interface {

	// Data returns the DHT block data (unstructured)
	Data() []byte

	// Verify the integrity of a block (optional). Override in custom query
	// types to implement block-specific integrity checks (see GNSBlock for
	// example). This verification is usually weaker than the verification
	// method from a Query (see GNSBlock.Verify for explanation).
	Verify() error
}

// Unwrap (raw) block to a specific block type
func Unwrap(blk Block, obj interface{}) error {
	return data.Unmarshal(obj, blk.Data())
}

//----------------------------------------------------------------------
// Generic interface implementations without persistent attributes
//----------------------------------------------------------------------

// GenericQuery is the binary representation of a DHT key
type GenericQuery struct {
	key *crypto.HashCode
}

// Key interface method implementation
func (k *GenericQuery) Key() *crypto.HashCode {
	return k.key
}

// Type returns the desired block type for results
func (k *GenericQuery) Type() uint16 {
	return DHT_BLOCK_ANY
}

// Verify interface method implementation
func (k *GenericQuery) Verify(b Block) error {
	// no verification, no errors ;)
	return nil
}

// Decrypt interface method implementation
func (k *GenericQuery) Decrypt(b Block) error {
	// no decryption, no errors ;)
	return nil
}

// NewGenericQuery creates a simple Query from hash code.
func NewGenericQuery(buf []byte) *GenericQuery {
	return &GenericQuery{
		key: crypto.NewHashCode(buf),
	}
}

// GenericBlock is the block in simple binary representation
type GenericBlock struct {
	data []byte `size:"*"`
}

// Data interface method implementation
func (b *GenericBlock) Data() []byte {
	return b.data
}

// Verify interface method implementation
func (b *GenericBlock) Verify() error {
	// no verification, no errors ;)
	return nil
}

// NewGenericBlock creates a Block from binary data.
func NewGenericBlock(buf []byte) *GenericBlock {
	return &GenericBlock{
		data: util.Clone(buf),
	}
}
