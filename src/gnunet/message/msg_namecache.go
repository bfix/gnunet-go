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
	"gnunet/enums"
	"gnunet/service/dht/blocks"
	"gnunet/util"
)

//----------------------------------------------------------------------
// Generic Namecache message header
//----------------------------------------------------------------------

// GenericNamecacheMsg is the common header for Namestore messages
type GenericNamecacheMsg struct {
	MsgHeader
	ID uint32 `order:"big"` // unique reference ID
}

// return initialized common message header
func newGenericNamecacheMsg(size uint16, mtype enums.MsgType) GenericNamecacheMsg {
	return GenericNamecacheMsg{
		MsgHeader: MsgHeader{size, mtype},
		ID:        uint32(util.NextID()),
	}
}

//----------------------------------------------------------------------
// NAMECACHE_LOOKUP_BLOCK
//----------------------------------------------------------------------

// NamecacheLookupMsg is request message for lookups in local namecache
type NamecacheLookupMsg struct {
	GenericNamecacheMsg

	Query *crypto.HashCode // Query data
}

// NewNamecacheLookupMsg creates a new default message.
func NewNamecacheLookupMsg(query *crypto.HashCode) *NamecacheLookupMsg {
	if query == nil {
		query = crypto.NewHashCode(nil)
	}
	return &NamecacheLookupMsg{
		GenericNamecacheMsg: newGenericNamecacheMsg(72, enums.MSG_NAMECACHE_LOOKUP_BLOCK),
		Query:               query,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamecacheLookupMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamecacheLookupMsg) String() string {
	return fmt.Sprintf("NamecacheLookupMsg{Id=%d,Query=%s}",
		m.ID, hex.EncodeToString(m.Query.Data))
}

//----------------------------------------------------------------------
// NAMECACHE_LOOKUP_BLOCK_RESPONSE
//----------------------------------------------------------------------

// NamecacheLookupResultMsg is the response message for namecache lookups.
type NamecacheLookupResultMsg struct {
	GenericNamecacheMsg

	Expire        util.AbsoluteTime     ``            // Expiration time
	DerivedKeySig *crypto.ZoneSignature `init:"Init"` // Derived public key
	EncData       []byte                `size:"*"`    // Encrypted block data
}

// Init called after unmarshalling a message to setup internal state
func (m *NamecacheLookupResultMsg) Init() error { return nil }

// NewNamecacheLookupResultMsg creates a new default message.
func NewNamecacheLookupResultMsg() *NamecacheLookupResultMsg {
	return &NamecacheLookupResultMsg{
		GenericNamecacheMsg: newGenericNamecacheMsg(112, enums.MSG_NAMECACHE_LOOKUP_BLOCK_RESPONSE),
		Expire:              util.AbsoluteTimeNever(),
		DerivedKeySig:       nil,
		EncData:             nil,
	}
}

// String returns a human-readable representation of the message.
func (m *NamecacheLookupResultMsg) String() string {
	return fmt.Sprintf("NamecacheLookupResultMsg{id=%d,expire=%s}",
		m.ID, m.Expire)
}

//----------------------------------------------------------------------
// NAMECACHE_CACHE_BLOCK
//----------------------------------------------------------------------

// NamecacheCacheMsg is the request message to put a name into the local cache.
type NamecacheCacheMsg struct {
	GenericNamecacheMsg

	Expire     util.AbsoluteTime ``                 // Expiration time
	DerivedSig []byte            `size:"(FldSize)"` // Derived signature
	DerivedKey []byte            `size:"(FldSize)"` // Derived public key
	EncData    []byte            `size:"*"`         // Encrypted block data
}

// Init called after unmarshalling a message to setup internal state
func (m *NamecacheCacheMsg) Init() error { return nil }

// Size returns buffer sizes for fields
func (m *NamecacheCacheMsg) FldSize(field string) uint {
	switch field {
	case "DerivedSig":
		return 64
	case "DerivedKey":
		return 36
	}
	// defaults to empty buffer
	return 0
}

// NewNamecacheCacheMsg creates a new default message.
func NewNamecacheCacheMsg(block *blocks.GNSBlock) *NamecacheCacheMsg {
	msg := &NamecacheCacheMsg{
		GenericNamecacheMsg: newGenericNamecacheMsg(116, enums.MSG_NAMECACHE_BLOCK_CACHE),
		Expire:              util.AbsoluteTimeNever(),
		DerivedSig:          nil,
		DerivedKey:          nil,
		EncData:             make([]byte, 0),
	}
	if block != nil {
		msg.DerivedKey = util.Clone(block.DerivedKeySig.ZoneKey.Bytes())
		msg.DerivedSig = util.Clone(block.DerivedKeySig.Signature)
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
	return fmt.Sprintf("NamecacheCacheMsg{size=%d,id=%d,expire=%s}",
		m.Size(), m.ID, m.Expire)
}

//----------------------------------------------------------------------
// NAMECACHE_BLOCK_CACHE_RESPONSE
//----------------------------------------------------------------------

// NamecacheCacheResponseMsg is the response message for a put request
type NamecacheCacheResponseMsg struct {
	GenericNamecacheMsg

	Result int32 `order:"big"` // Result code
}

// NewNamecacheCacheResponseMsg creates a new default message.
func NewNamecacheCacheResponseMsg() *NamecacheCacheResponseMsg {
	return &NamecacheCacheResponseMsg{
		GenericNamecacheMsg: newGenericNamecacheMsg(12, enums.MSG_NAMECACHE_BLOCK_CACHE_RESPONSE),
		Result:              0,
	}
}

// Init called after unmarshalling a message to setup internal state
func (m *NamecacheCacheResponseMsg) Init() error { return nil }

// String returns a human-readable representation of the message.
func (m *NamecacheCacheResponseMsg) String() string {
	return fmt.Sprintf("NamecacheCacheResponseMsg{id=%d,result=%d}",
		m.ID, m.Result)
}
