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
	Type() enums.BlockType

	// Flags returns the query flags
	Flags() uint16

	// Params holds additional info for queries
	Params() util.ParameterSet

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

	// Bytes returns the DHT block data (unstructured without type and
	// expiration information.
	Bytes() []byte

	// Return the block type
	Type() enums.BlockType

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
	return data.Unmarshal(obj, blk.Bytes())
}

//----------------------------------------------------------------------
// Generic interface implementations without persistent attributes
//----------------------------------------------------------------------

// GenericQuery is the binary representation of a DHT key
type GenericQuery struct {
	// Key for repository queries (local/remote)
	key *crypto.HashCode

	// block type requested
	btype enums.BlockType

	// query flags
	flags uint16

	// Params holds additional query parameters
	params util.ParameterSet
}

// Key interface method implementation
func (q *GenericQuery) Key() *crypto.HashCode {
	return q.key
}

// Type returns the requested block type
func (q *GenericQuery) Type() enums.BlockType {
	return q.btype
}

// Flags returns the query flags
func (q *GenericQuery) Flags() uint16 {
	return q.flags
}

// Params holds additional info for queries
func (q *GenericQuery) Params() util.ParameterSet {
	return q.params
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
	return fmt.Sprintf("GenericQuery{btype=%s,key=%s}", q.btype, q.Key().Short())
}

// NewGenericQuery creates a simple Query from hash code.
func NewGenericQuery(key *crypto.HashCode, btype enums.BlockType, flags uint16) *GenericQuery {
	return &GenericQuery{
		key:    key,
		btype:  btype,
		flags:  flags,
		params: make(util.ParameterSet),
	}
}

//----------------------------------------------------------------------
// Generic block (custom implementation unknown to gnunet-go)
//----------------------------------------------------------------------

// GenericBlock is used for custom blocks not known to the DHT
type GenericBlock struct {
	BType   enums.BlockType   // block type
	Expire_ util.AbsoluteTime // expiration time
	Data    []byte            // block data
}

// NewGenericBlock creates a custom block instance
func NewGenericBlock(btype enums.BlockType, expire util.AbsoluteTime, blk []byte) Block {
	return &GenericBlock{
		BType:   btype,
		Expire_: expire,
		Data:    util.Clone(blk),
	}
}

// Bytes returns the DHT block data (unstructured without type and
// expiration information.
func (b *GenericBlock) Bytes() []byte {
	return util.Clone(b.Data)
}

// Return the block type
func (b *GenericBlock) Type() enums.BlockType {
	return b.BType
}

// Expire returns the block expiration
func (b *GenericBlock) Expire() util.AbsoluteTime {
	return b.Expire_
}

// Verify the integrity of a block (optional). Override in custom query
// types to implement block-specific integrity checks (see GNSBlock for
// example). This verification is usually weaker than the verification
// method from a Query (see GNSBlock.Verify for explanation).
func (b *GenericBlock) Verify() (bool, error) {
	return true, nil
}

// String returns the human-readable representation of a block
func (b *GenericBlock) String() string {
	return fmt.Sprintf("Block{type=%s,expire=%s,data=[%d]}", b.BType, b.Expire_, len(b.Data))
}

//----------------------------------------------------------------------
// Block factory: extend for custom block types
//----------------------------------------------------------------------

// Known block factories
var (
	blkFactory = map[enums.BlockType]func() Block{
		enums.BLOCK_TYPE_GNS_NAMERECORD: NewGNSBlock,
		enums.BLOCK_TYPE_DHT_URL_HELLO:  NewHelloBlock,
		enums.BLOCK_TYPE_TEST:           NewTestBlock,
	}
)

// NewGenericBlock creates a Block from binary data.
func NewBlock(btype enums.BlockType, expires util.AbsoluteTime, blk []byte) (b Block, err error) {
	fac, ok := blkFactory[btype]
	if !ok {
		return NewGenericBlock(btype, expires, blk), nil
	}
	b = fac()
	err = data.Unmarshal(b, blk)
	return
}
