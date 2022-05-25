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

	"github.com/bfix/gospel/data"
)

// DHT Query interface
type Query interface {

	// Key returns the DHT key for a block
	Key() *crypto.HashCode

	// Verify the integrity of a retrieved block
	Verify(blk Block) error

	// Decrypt block content
	Decrypt(blk Block) error
}

// DHT Block interface
type Block interface {
	Data() []byte
}

// Unwrap block to specific block type
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

// NewGenericQuery creates a simple Query from binary key data.
func NewGenericQuery(h *crypto.HashCode) *GenericQuery {
	return &GenericQuery{
		key: h,
	}
}

// GenericBlock is the block in simple binary representation
type GenericBlock struct {
	data []byte
}

// Data interface method implementation
func (b *GenericBlock) Data() []byte {
	return b.data
}

// NewGenericBlock creates a Block from binary data.
func NewGenericBlock(buf []byte) *GenericBlock {
	return &GenericBlock{
		data: buf,
	}
}
