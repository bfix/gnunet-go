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

package message

import (
	"encoding/hex"
	"fmt"
	"gnunet/crypto"
	"gnunet/service/dht/blocks"
	"gnunet/util"
)

//----------------------------------------------------------------------
// NAMECACHE_LOOKUP_BLOCK
//----------------------------------------------------------------------

// NamecacheLookupMsg is request message for lookups in local namecache
type NamecacheLookupMsg struct {
	MsgSize uint16           `order:"big"` // total size of message
	MsgType uint16           `order:"big"` // NAMECACHE_LOOKUP_BLOCK (431)
	ID      uint32           `order:"big"` // Request Id
	Query   *crypto.HashCode // Query data
}

// NewNamecacheLookupMsg creates a new default message.
func NewNamecacheLookupMsg(query *crypto.HashCode) *NamecacheLookupMsg {
	if query == nil {
		query = crypto.NewHashCode(nil)
	}
	return &NamecacheLookupMsg{
		MsgSize: 72,
		MsgType: NAMECACHE_LOOKUP_BLOCK,
		ID:      0,
		Query:   query,
	}
}

// String returns a human-readable representation of the message.
func (m *NamecacheLookupMsg) String() string {
	return fmt.Sprintf("NamecacheLookupMsg{Id=%d,Query=%s}",
		m.ID, hex.EncodeToString(m.Query.Bits))
}

// Header returns the message header in a separate instance.
func (m *NamecacheLookupMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// NAMECACHE_LOOKUP_BLOCK_RESPONSE
//----------------------------------------------------------------------

// NamecacheLookupResultMsg is the response message for namecache lookups.
type NamecacheLookupResultMsg struct {
	MsgSize       uint16                `order:"big"` // total size of message
	MsgType       uint16                `order:"big"` // NAMECACHE_LOOKUP_BLOCK_RESPONSE (432)
	ID            uint32                `order:"big"` // Request Id
	Expire        util.AbsoluteTime     ``            // Expiration time
	DerivedKeySig *crypto.ZoneSignature ``            // Derived public key
	EncData       []byte                `size:"*"`    // Encrypted block data
}

// NewNamecacheLookupResultMsg creates a new default message.
func NewNamecacheLookupResultMsg() *NamecacheLookupResultMsg {
	return &NamecacheLookupResultMsg{
		MsgSize:       112,
		MsgType:       NAMECACHE_LOOKUP_BLOCK_RESPONSE,
		ID:            0,
		Expire:        *new(util.AbsoluteTime),
		DerivedKeySig: nil,
		EncData:       nil,
	}
}

// String returns a human-readable representation of the message.
func (m *NamecacheLookupResultMsg) String() string {
	return fmt.Sprintf("NamecacheLookupResultMsg{id=%d,expire=%s}",
		m.ID, m.Expire)
}

// Header returns the message header in a separate instance.
func (m *NamecacheLookupResultMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// NAMECACHE_CACHE_BLOCK
//----------------------------------------------------------------------

// NamecacheCacheMsg is the request message to put a name into the local cache.
type NamecacheCacheMsg struct {
	MsgSize       uint16                `order:"big"` // total size of message
	MsgType       uint16                `order:"big"` // NAMECACHE_CACHE_BLOCK (433)
	ID            uint32                `order:"big"` // Request Id
	Expire        util.AbsoluteTime     ``            // Expiration time
	DerivedKeySig *crypto.ZoneSignature ``            // Derived public key and signature
	EncData       []byte                `size:"*"`    // Encrypted block data
}

// NewNamecacheCacheMsg creates a new default message.
func NewNamecacheCacheMsg(block *blocks.GNSBlock) *NamecacheCacheMsg {
	msg := &NamecacheCacheMsg{
		MsgSize:       108,
		MsgType:       NAMECACHE_BLOCK_CACHE,
		ID:            0,
		Expire:        *new(util.AbsoluteTime),
		DerivedKeySig: nil,
		EncData:       make([]byte, 0),
	}
	if block != nil {
		msg.DerivedKeySig = block.DerivedKeySig
		msg.Expire = block.Body.Expire
		size := len(block.Body.Data)
		msg.EncData = make([]byte, size)
		copy(msg.EncData, block.Body.Data)
		msg.MsgSize += uint16(size)
	}
	return msg
}

// String returns a human-readable representation of the message.
func (m *NamecacheCacheMsg) String() string {
	return fmt.Sprintf("NewNamecacheCacheMsg{id=%d,expire=%s}",
		m.ID, m.Expire)
}

// Header returns the message header in a separate instance.
func (m *NamecacheCacheMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}

//----------------------------------------------------------------------
// NAMECACHE_BLOCK_CACHE_RESPONSE
//----------------------------------------------------------------------

// NamecacheCacheResponseMsg is the reponse message for a put request
type NamecacheCacheResponseMsg struct {
	MsgSize uint16 `order:"big"` // total size of message
	MsgType uint16 `order:"big"` // NAMECACHE_LOOKUP_BLOCK_RESPONSE (432)
	ID      uint32 `order:"big"` // Request Id
	Result  int32  `order:"big"` // Result code
}

// NewNamecacheCacheResponseMsg creates a new default message.
func NewNamecacheCacheResponseMsg() *NamecacheCacheResponseMsg {
	return &NamecacheCacheResponseMsg{
		MsgSize: 12,
		MsgType: NAMECACHE_BLOCK_CACHE_RESPONSE,
		ID:      0,
		Result:  0,
	}
}

// String returns a human-readable representation of the message.
func (m *NamecacheCacheResponseMsg) String() string {
	return fmt.Sprintf("NamecacheCacheResponseMsg{id=%d,result=%d}",
		m.ID, m.Result)
}

// Header returns the message header in a separate instance.
func (m *NamecacheCacheResponseMsg) Header() *Header {
	return &Header{m.MsgSize, m.MsgType}
}
