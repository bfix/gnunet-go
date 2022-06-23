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
	"encoding/hex"
	"fmt"
	"gnunet/crypto"
	"gnunet/enums"
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

	// Type returns the requested block type
	Type() uint16

	// Flags returns the query flags
	Flags() uint16

	// Verify the integrity of a retrieved block (optional). Override in
	// custom query types to implement block-specific integrity checks
	// (see GNSQuery for example).
	Verify(blk Block) error

	// Decrypt block content (optional). Override in custom query types to
	// implement block-specific encryption (see GNSQuery for example).
	Decrypt(blk Block) error

	// String returns the human-readable representation of a query
	String() string
}

// DHT Block interface
type Block interface {

	// Data returns the DHT block data (unstructured without type and
	// expiration information.
	Data() []byte

	// Return the block type
	Type() uint16

	// Expire returns the block expiration
	Expire() util.AbsoluteTime

	// Verify the integrity of a block (optional). Override in custom query
	// types to implement block-specific integrity checks (see GNSBlock for
	// example). This verification is usually weaker than the verification
	// method from a Query (see GNSBlock.Verify for explanation).
	Verify() (bool, error)

	// String returns the human-readable representation of a block
	String() string
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
	// Key for repository queries (local/remote)
	key *crypto.HashCode

	// block type requested
	btype uint16

	// query flags
	flags uint16

	// Params holds additional query parameters
	Params util.ParameterSet
}

// Key interface method implementation
func (q *GenericQuery) Key() *crypto.HashCode {
	return q.key
}

// Type returns the requested block type
func (q *GenericQuery) Type() uint16 {
	return q.btype
}

// Flags returns the query flags
func (q *GenericQuery) Flags() uint16 {
	return q.flags
}

// Verify interface method implementation
func (q *GenericQuery) Verify(b Block) error {
	// no verification, no errors ;)
	return nil
}

// Decrypt interface method implementation
func (q *GenericQuery) Decrypt(b Block) error {
	// no decryption, no errors ;)
	return nil
}

// String returns the human-readable representation of a block
func (q *GenericQuery) String() string {
	return fmt.Sprintf("GenericQuery{btype=%d,key=%s}", q.btype, hex.EncodeToString(q.Key().Bits))
}

// NewGenericQuery creates a simple Query from hash code.
func NewGenericQuery(key []byte, btype enums.BlockType, flags uint16) *GenericQuery {
	return &GenericQuery{
		key:    crypto.NewHashCode(key),
		btype:  uint16(btype),
		flags:  flags,
		Params: make(util.ParameterSet),
	}
}

//----------------------------------------------------------------------

// GenericBlock is the block in simple binary representation
type GenericBlock struct {
	block  []byte            // block data
	btype  uint16            // block type
	expire util.AbsoluteTime // expiration date
}

// Data interface method implementation
func (b *GenericBlock) Data() []byte {
	return b.block
}

// Type returns the block type
func (b *GenericBlock) Type() uint16 {
	return b.btype
}

// Expire returns the block expiration
func (b *GenericBlock) Expire() util.AbsoluteTime {
	return b.expire
}

// String returns the human-readable representation of a block
func (b *GenericBlock) String() string {
	return fmt.Sprintf("GenericBlock{type=%d,expires=%s,data=[%d]}",
		b.btype, b.expire.String(), len(b.block))
}

// Verify interface method implementation
func (b *GenericBlock) Verify() (bool, error) {
	// no verification, no errors ;)
	return true, nil
}

// NewGenericBlock creates a Block from binary data.
func NewGenericBlock(buf []byte) *GenericBlock {
	return &GenericBlock{
		block:  util.Clone(buf),
		btype:  uint16(enums.BLOCK_TYPE_ANY), // unknown block type
		expire: util.AbsoluteTimeNever(),     // never expires
	}
}
